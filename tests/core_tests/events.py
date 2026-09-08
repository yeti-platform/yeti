import base64
import json
import os
import unittest

import redis

from core import database_arango
from core.config.config import yeti_config
from core.events import message, producer
from core.schemas import agent_persona, observable


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
        self.assertEqual(self.redis_client.llen("events"), 3)
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
        # 1 event for the tag event
        # 1 event for the host's tag update
        self.assertEqual(self.redis_client.llen("events"), 5)
        redis_payload = self.redis_client.lpop("events")
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


class EventUnionCoverageTest(unittest.TestCase):
    """Guards the two ways an object can fail to become an event.

    Both are silent: publishing is wrapped in a try/except that logs, so the
    write still lands and only the log says anything. AgentPersona shipped
    broken on both counts without any test noticing.
    """

    # Written to, but deliberately never published: save() and delete() skip
    # these by collection name. An event per audit-log line would be circular.
    NEVER_PUBLISHED = {"auditlog", "timeline"}
    # Publishes a LinkEvent, which names its objects rather than discriminating
    # on them.
    LINK_COLLECTION = "links"

    def publishing_classes(self):
        import core.schemas  # noqa: F401  (registers every schema type)

        def descendants(cls):
            for sub in cls.__subclasses__():
                yield sub
                yield from descendants(sub)

        seen = {}
        for cls in descendants(database_arango.ArangoYetiConnector):
            collection = getattr(cls, "_collection_name", None)
            if collection in self.NEVER_PUBLISHED or collection is None:
                continue
            if collection == self.LINK_COLLECTION:
                continue
            root_type = cls.__private_attributes__.get("_root_type")
            if root_type is not None:
                seen[cls] = root_type.default
        return seen

    def test_every_published_object_exposes_root_type(self):
        """The discriminator reads `root_type` off the instance. A class with
        only the private `_root_type` resolves to no tag at all."""
        for cls in self.publishing_classes():
            self.assertIn(
                "root_type",
                cls.model_fields | cls.model_computed_fields,
                f"{cls.__name__} does not expose root_type",
            )

    def test_every_published_root_type_has_a_union_member(self):
        """A root_type absent from YetiObjectTypes raises union_tag_not_found
        on every save and delete of that object."""
        import typing

        union, _ = typing.get_args(message.YetiObjectTypes)
        tags = set()
        for member in typing.get_args(union):
            for meta in getattr(member, "__metadata__", ()):
                tag = getattr(meta, "tag", None)
                if tag:
                    tags.add(tag)

        missing = {
            root_type
            for root_type in self.publishing_classes().values()
            if root_type not in tags
        }
        self.assertEqual(missing, set(), f"root types with no union member: {missing}")


class AgentPersonaEventsTest(unittest.TestCase):
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

    def persona(self):
        return agent_persona.AgentPersona(
            name="Default", instruction="Be helpful, and be brief about it."
        )

    def test_saving_a_persona_publishes_an_event(self) -> None:
        saved = self.persona().save()

        self.assertEqual(self.redis_client.llen("events"), 1)
        body = json.loads(
            base64.b64decode(json.loads(self.redis_client.lpop("events"))["body"])
        )
        event = message.EventMessage(**json.loads(body))
        self.assertEqual(event.event.type, message.EventType.new)
        self.assertEqual(event.event.yeti_object.id, saved.id)
        self.assertEqual(event.event.yeti_object.name, "Default")

    def test_deleting_a_persona_publishes_an_event(self) -> None:
        saved = self.persona().save()
        self.redis_client.delete("events")

        saved.delete()

        self.assertEqual(self.redis_client.llen("events"), 1)
        body = json.loads(
            base64.b64decode(json.loads(self.redis_client.lpop("events"))["body"])
        )
        event = message.EventMessage(**json.loads(body))
        self.assertEqual(event.event.type, message.EventType.delete)
        self.assertEqual(event.event.yeti_object.name, "Default")
