import json
import threading
import traceback

from kombu import Connection, Exchange, Queue
from kombu.mixins import ConsumerMixin

from core.config.config import yeti_config
from core.events.message import EventData, LogData, Message, MessageType
from core.schemas.task import Task, TaskType
from core.taskscheduler import run_task


class Worker(ConsumerMixin):
    EVENT_TASKS = [TaskType.inline, TaskType.metric, TaskType.forward]

    def __init__(self, connection, queues):
        self.connection = connection
        self.queues = queues

    def get_consumers(self, consumer, channel):
        return [
            consumer(queues=self.queues, callbacks=[self.on_message], accept=["json"])
        ]

    def _handle_event(self, data: EventData):
        for task in Task.list():
            if task.enabled is False:
                continue
            if task.type in Worker.EVENT_TASKS and (
                data.event in task.acts_on or not task.acts_on
            ):
                params = json.dumps({"params": {"id": data.object_id}})
                run_task.apply_async(args=[task.name, params], queue=task.type)

    def _handle_log(self, data: LogData):
        for task in Task.list():
            if task.enabled is False:
                continue
            if task.type == TaskType.log:
                params = json.dumps({"params": {"log": data.log}})
                run_task.apply_async(args=[task.name, params], queue="log")

    def on_message(self, body, received_message):
        try:
            message = Message(**body)
            if message.type == MessageType.event:
                self._handle_event(message.data)
            if message.type == MessageType.log:
                self._handle_log(message.data)
        except Exception:
            traceback.print_exc()
        received_message.ack()


def consume_events():
    exchange = Exchange("events", type="direct")
    queues = [Queue("events", exchange, routing_key="events")]
    broker = f"redis://{yeti_config.get('redis', 'host')}/"
    with Connection(broker, heartbeat=4) as conn:
        worker = Worker(conn, queues)
        worker.run()


# events_consumer_thread = threading.Thread(name='consumer', target=consume_events)
# events_consumer_thread.start()

consume_events()
