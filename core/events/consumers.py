import argparse
import hashlib
import json
import logging
import multiprocessing
import os

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


class Consumer(ConsumerMixin):
    def __init__(self, task_class: EventTask | LogTask, stop_event, connection, queues):
        self.task_class = task_class
        self._stop_event = stop_event
        self.connection = connection
        self.queues = queues
        self._logger = None
        get_plugins_list(task_class)

    @property
    def should_stop(self):
        return self._stop_event.is_set()

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


class EventConsumer(Consumer):
    def __init__(self, stop_event, connection, queues):
        super().__init__(EventTask, stop_event, connection, queues)

    def on_message(self, body, received_message):
        try:
            message = EventMessage(**json.loads(body))
            message_digest = hashlib.sha256(body.encode()).hexdigest()
            ts = int(message.timestamp.timestamp())
            self.logger.debug(f"Message received at {ts} - digest: {message_digest}")
            for task in TaskManager.tasks():
                if task.enabled is False or task.type != TaskType.event:
                    continue
                if message.event.match(task.compiled_acts_on):
                    self.logger.info(f"Running task {task.name}")
                    task.run(message)
        except Exception:
            self.logger.exception(
                f"[PID:{os.getpid()}] - Error processing message in events queue with {body}"
            )
        received_message.ack()


class LogConsumer(Consumer):
    def __init__(self, stop_event, connection, queues):
        super().__init__(LogTask, stop_event, connection, queues)

    def on_message(self, body, received_message):
        try:
            message = LogMessage(**json.loads(body))
            for task in TaskManager.tasks():
                if task.enabled is False or task.type != TaskType.log:
                    continue
                task.run(message)
        except Exception:
            self.logger.exception(f"Error processing message in logs queue with {body}")
        received_message.ack()


class Worker(multiprocessing.Process):
    def __init__(self, queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_event = multiprocessing.Event()
        exchange = Exchange(queue, type="direct")
        queues = [Queue(queue, exchange, routing_key=queue)]
        broker = f"redis://{yeti_config.get('redis', 'host')}/"
        self._connection = Connection(broker, heartbeat=4)
        self._connection.connect()
        self._worker = EventConsumer(self.stop_event, self._connection, queues)

    def run(self):
        logger.info(f"Worker {self.name} started")
        while not self.stop_event.is_set():
            try:
                self._worker.run()
            except Exception:
                logger.exception("Consumer failed, restarting")
            except KeyboardInterrupt:
                logger.info(f"Worker {self.name} exiting...")
        self._connection.release()
        return


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
    if not args.concurrency:
        concurrency = multiprocessing.cpu_count()
    else:
        concurrency = args.concurrency
    logger.info(f"Starting {concurrency} {args.type} workers")
    processes = []
    stop_event = multiprocessing.Event()
    for i in range(concurrency):
        name = f"{args.type}-worker-{i+1}"
        p = Worker(queue=args.type, name=name)
        p.start()
        logger.info(f"Starting {p.name} pid={p.pid}")
        processes.append(p)
    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        logger.info("Shutdown requested, exiting gracefully...")
    try:
        logger.info(f"Terminating worker {p.name} pid={p.pid}")
        for p in processes:
            p.stop_event.set()
            p.join()
            logger.info(f"Worker {p.name} pid={p.pid} exited")
    except KeyboardInterrupt:
        logger.info("Forcefully killing remaining workers")
        for p in processes:
            p.kill()
            logger.info(f"Worker {p.name} pid={p.pid} killed")
