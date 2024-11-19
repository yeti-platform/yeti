import base64
import json
import os
import unittest

import redis

from core import database_arango
from core.config.config import yeti_config
from core.events import message, producer
from core.schemas import observable


class EventsTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.redis_client = redis.from_url(
            f"redis://{yeti_config.get('redis', 'host')}/"
        )
        self.redis_client.delete("events")

    def tearDown(self) -> None:
        database_arango.db.clear()
        self.redis_client.delete("events")

    def test_publish_new_object_event(self) -> None:
        obs1 = observable.Hostname(value="test1.com").save()
        self.assertEqual(self.redis_client.llen("events"), 1)
        redis_payload = self.redis_client.lpop("events")
        body_payload = json.loads(redis_payload).get("body")
        body = json.loads(base64.b64decode(body_payload))
        event = message.EventMessage(**json.loads(body))
        self.assertEqual(event.event.type, message.EventType.new)
        self.assertEqual(event.event.yeti_object.id, obs1.id)
        self.assertEqual(event.event.yeti_object.value, "test1.com")

    def test_publish_update_object_event(self) -> None:
        obs1 = observable.UserAccount(value="foobar").save()
        obs1.account_type = "admin"
        obs1 = obs1.save()
        self.assertEqual(self.redis_client.llen("events"), 2)
        redis_payload = self.redis_client.lpop("events")
        body_payload = json.loads(redis_payload).get("body")
        body = json.loads(base64.b64decode(body_payload))
        event = message.EventMessage(**json.loads(body))
        self.assertEqual(event.event.type, message.EventType.update)
        self.assertEqual(event.event.yeti_object.id, obs1.id)
        self.assertEqual(event.event.yeti_object.value, "foobar")

    def test_publish_delete_object_event(self) -> None:
        obs1 = observable.Hostname(value="test1.com").save()
        self.assertEqual(self.redis_client.llen("events"), 1)
        obs1.delete()
        self.assertEqual(self.redis_client.llen("events"), 2)
        redis_payload = self.redis_client.lpop("events")
        body_payload = json.loads(redis_payload).get("body")
        body = json.loads(base64.b64decode(body_payload))
        event = message.EventMessage(**json.loads(body))
        self.assertEqual(event.event.type, message.EventType.delete)
        self.assertEqual(event.event.yeti_object.id, obs1.id)
        self.assertEqual(event.event.yeti_object.value, "test1.com")

    def test_publish_link_event(self) -> None:
        obs1 = observable.Hostname(value="test1.com").save()
        obs2 = observable.Hostname(value="test2.com").save()
        obs1.link_to(obs2, "test", "description")
        self.assertEqual(self.redis_client.llen("events"), 3)
        redis_payload = self.redis_client.lpop("events")
        body_payload = json.loads(redis_payload).get("body")
        body = json.loads(base64.b64decode(body_payload))
        event = message.EventMessage(**json.loads(body))
        self.assertIsInstance(event.event, message.LinkEvent)
        self.assertEqual(event.event.type, message.EventType.new)
        self.assertEqual(event.event.source_object.id, obs1.id)
        self.assertEqual(event.event.source_object.value, "test1.com")
        self.assertEqual(event.event.target_object.id, obs2.id)
        self.assertEqual(event.event.target_object.value, "test2.com")

    def test_publish_tag_event(self) -> None:
        obs1 = observable.Hostname(value="test1.com").save()
        obs1.tag(["test"])
        # 1 event for the object creation,
        # 1 event for the tag creation
        # 1 event for the tag count update
        # 1 event for the tag association
        self.assertEqual(self.redis_client.llen("events"), 4)
        redis_payload = self.redis_client.lpop("events")
        body_payload = json.loads(redis_payload).get("body")
        body = json.loads(base64.b64decode(body_payload))
        event = message.EventMessage(**json.loads(body))
        self.assertIsInstance(event.event, message.TagEvent)
        self.assertEqual(event.event.type, message.EventType.new)
        self.assertEqual(event.event.tagged_object.id, obs1.id)
        self.assertEqual(event.event.tagged_object.value, "test1.com")
        self.assertEqual(event.event.tag_object.name, "test")

    def test_invalid_keep_ratio(self) -> None:
        os.environ["YETI_CONFIG_EVENTS_KEEP_RATIO"] = "-0.1"
        producer_instance = producer.EventProducer()
        self.assertEqual(producer_instance._keep_ratio, 0.9)
        os.environ["YETI_CONFIG_EVENTS_KEEP_RATIO"] = "1"
        producer_instance = producer.EventProducer()
        self.assertEqual(producer_instance._keep_ratio, 0.9)

    def test_low_memory_limit(self) -> None:
        os.environ["YETI_CONFIG_EVENTS_MEMORY_LIMIT"] = "32"
        producer_instance = producer.EventProducer()
        self.assertEqual(producer_instance._memory_limit, 64 * 1024 * 1024)

    def test_queue_memory_limit(self) -> None:
        # override the memory limit to 10KB for testing
        producer.producer._memory_limit = 10 * 1024
        i = 0
        trimmed = False
        while not trimmed:
            i += 1
            obs = observable.Hostname(value=f"test{i}.com").save()
            evt = message.ObjectEvent(type=message.EventType.new, yeti_object=obs)
            msg = message.EventMessage(event=evt)
            producer.producer.event_producer.publish(msg.model_dump_json())
            if producer.producer._trim_queue_size("events"):
                trimmed = True
        self.assertAlmostEqual(
            self.redis_client.memory_usage("events"),
            producer.producer._memory_limit,
            delta=1024,
        )
        redis_payload = self.redis_client.lpop("events")
        body_payload = json.loads(redis_payload).get("body")
        body = json.loads(base64.b64decode(body_payload))
        event = message.EventMessage(**json.loads(body))
        self.assertEqual(event.event.yeti_object.value, f"test{i}.com")
