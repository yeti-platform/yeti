import argparse
import hashlib
import json
import logging
import multiprocessing
import os
import re

from kombu import Connection, Exchange, Queue
from kombu.mixins import ConsumerMixin

from core.config.config import yeti_config
from core.events.message import EventMessage, LogMessage
from core.schemas.task import EventTask, LogTask, TaskType
from core.taskmanager import TaskManager
from core.taskscheduler import get_plugins_list

# Register root logger for tasks
logger = logging.getLogger("task")
logger.propagate = False
formatter = logging.Formatter(
    "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s"
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


class Worker(ConsumerMixin):
    def __init__(self, task_class: EventTask | LogTask, connection, queues):
        self.task_class = task_class
        self.connection = connection
        self.queues = queues
        self._logger = None
        get_plugins_list(task_class)

    @property
    def logger(self):
        if self._logger is None:
            name = self.task_class.__name__.lower().replace("task", "")
            self._logger = logging.getLogger(f"task.{name}")
            self._logger.propagate = False
            formatter = logging.Formatter(
                "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s"
            )
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
        return self._logger

    def get_consumers(self, consumer, channel):
        return [
            consumer(queues=self.queues, callbacks=[self.on_message], accept=["json"])
        ]


class EventWorker(Worker):
    def __init__(self, connection, queues):
        super().__init__(EventTask, connection, queues)

    def on_message(self, body, received_message):
        try:
            message = EventMessage(**json.loads(body))
            message_digest = hashlib.sha256(body.encode()).hexdigest()
            self.logger.debug(f"Message digest: {message_digest}")
            for task in TaskManager.tasks():
                if task.enabled is False or task.type != TaskType.event:
                    continue
                if message.event.match(task.acts_on):
                    self.logger.info(f"Running task {task.name}")
                    task.run(message.event)
        except Exception:
            self.logger.exception(
                f"[PID:{os.getpid()}] - Error processing message in events queue with {body}"
            )
        received_message.ack()


class LogWorker(Worker):
    def __init__(self, connection, queues):
        super().__init__(LogTask, connection, queues)

    def on_message(self, body, received_message):
        try:
            message = LogMessage(**json.loads(body))
            for task in TaskManager.tasks():
                if task.enabled is False or task.type != TaskType.log:
                    continue
                task.run(message.log)
        except Exception:
            self.logger.exception(f"Error processing message in logs queue with {body}")
        received_message.ack()


def event_worker():
    exchange = Exchange("events", type="direct")
    queues = [Queue("events", exchange, routing_key="events")]
    broker = f"redis://{yeti_config.get('redis', 'host')}/"
    with Connection(broker, heartbeat=4) as conn:
        worker = EventWorker(conn, queues)
        worker.run()


def log_worker():
    exchange = Exchange("logs", type="direct")
    queues = [Queue("logs", exchange, routing_key="logs")]
    broker = f"redis://{yeti_config.get('redis', 'host')}/"
    with Connection(broker, heartbeat=4) as conn:
        worker = LogWorker(conn, queues)
        worker.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="yeti-consumer", description="Consume events and logs from the event bus"
    )
    parser.add_argument(
        "--concurrency", type=int, default=None, help="Number of consumers to start"
    )
    parser.add_argument(
        "type", choices=["events", "logs"], help="Type of consumer to start"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    if args.type == "events":
        worker = event_worker
    elif args.type == "logs":
        worker = log_worker
    if not args.concurrency:
        concurrency = multiprocessing.cpu_count()
    else:
        concurrency = args.concurrency
    if concurrency > 1:
        logger.info(f"Starting {concurrency} {args.type} workers")
        try:
            processes = []
            for i in range(concurrency):
                name = f"{args.type}-worker-{i}"
                p = multiprocessing.Process(target=worker, name=name)
                p.start()
                logger.info(f"Started {p.name} pid={p.pid}")
                processes.append(p)
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            logger.info("Shutdown requested, exiting...")
            for p in processes:
                logger.info(f"Terminating worker {p.name} pid={p.pid}")
                p.terminate()
    else:
        logger.info(f"Starting {args.type} worker")
        worker()
