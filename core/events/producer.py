from kombu import Connection, Exchange, Producer, Queue

from core.config.config import yeti_config
from core.events.message import Message, MessageType


class EventProducer:
    def __init__(self):
        try:
            self.conn = Connection(f"redis://{yeti_config.get('redis', 'host')}/")
            self.channel = self.conn.channel()
            self.exchange = Exchange("events", type="direct")
            self.producer = Producer(
                exchange=self.exchange,
                channel=self.channel,
                routing_key="events",
                serializer="json",
            )
            self.queue = Queue(
                name="events", exchange=self.exchange, routing_key="events"
            )
            self.queue.maybe_bind(self.conn)
            self.queue.declare()
        except Exception as e:
            print(f"Error creating message producer: {e}")
            self.producer = None

    # Message is validated on consumer end
    def publish_event(self, event: str, object_id: str):
        if not self.producer:
            return
        message = {
            "type": MessageType.event,
            "data": {"event": event, "object_id": object_id},
        }
        self.producer.publish(message)
        self.publish_log(f"New event published: {event}:{object_id}")

    def publish_log(self, log: str | dict):
        if not self.producer:
            return
        message = {"type": MessageType.log, "data": {"log": log}}
        self.producer.publish(message)


producer = EventProducer()
