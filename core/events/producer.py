import logging

from kombu import Connection, Exchange, Producer, Queue

from core.config.config import yeti_config
from core.events.message import EventMessage, EventTypes, LogMessage


class EventProducer:
    def __init__(self):
        self.event_producer = None
        self.log_producer = None
        try:
            self.conn = Connection(f"redis://{yeti_config.get('redis', 'host')}/")
            self.channel = self.conn.channel()
            self.create_event_producer()
            self.create_log_producer()
        except Exception as e:
            logging.exception(f"Error creating producers: {e}")

    def create_event_producer(self):
        self.event_exchange = Exchange("events", type="direct")
        self.event_producer = Producer(
            exchange=self.event_exchange,
            channel=self.channel,
            routing_key="events",
            serializer="json",
        )
        self.event_queue = Queue(
            name="events", exchange=self.event_exchange, routing_key="events"
        )
        self.event_queue.maybe_bind(self.conn)
        self.event_queue.declare()

    def create_log_producer(self):
        self.log_exchange = Exchange("logs", type="direct")
        self.log_producer = Producer(
            exchange=self.log_exchange,
            channel=self.channel,
            routing_key="logs",
            serializer="json",
        )
        self.log_queue = Queue(
            name="logs", exchange=self.log_exchange, routing_key="logs"
        )
        self.log_queue.maybe_bind(self.conn)
        self.log_queue.declare()

    # Message is validated on consumer end
    def publish_event(self, event: EventTypes):
        if not self.event_producer:
            return
        try:
            message = EventMessage(event=event)
            self.event_producer.publish(message.model_dump_json())
        except Exception:
            logging.exception("Error publishing event")
        self.publish_log(f"New event published: {event}")

    def publish_log(self, log: str | dict):
        if not self.log_producer:
            return
        try:
            message = LogMessage(log=log)
            self.log_producer.publish(message.model_dump_json())
        except Exception:
            logging.exception("Error publishing log")


producer = EventProducer()
