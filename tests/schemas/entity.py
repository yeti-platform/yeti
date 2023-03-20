import datetime
import unittest

from core import database_arango
from core.schemas.entity import Entity, Malware, ThreatActor, Tool
from core.schemas.graph import Relationship
from core.schemas.observable import Observable


class EntityTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_create_entity(self) -> None:
        result = ThreatActor(name="APT0").save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "APT0")
        self.assertEqual(result.type, "threat-actor")

    def test_filter_entities_different_types(self) -> None:
        actor = ThreatActor(name="APT0").save()
        tool = Tool(name="xmrig").save()
        malware = Malware(name="plugx").save()

        all_entities = list(Entity.list())
        threat_actor_entities = list(ThreatActor.list())
        tool_entities = list(Tool.list())
        malware_entities = list(Malware.list())

        self.assertEqual(len(all_entities), 3)

        self.assertEqual(len(threat_actor_entities), 1)
        self.assertEqual(len(tool_entities), 1)
        self.assertEqual(len(malware_entities), 1)

        self.assertEqual(threat_actor_entities[0].json(), actor.json())
        self.assertEqual(tool_entities[0].json(), tool.json())
        self.assertEqual(malware_entities[0].json(), malware.json())

    def test_entity_with_tags(self):
        entity = ThreatActor(name="APT0", relevant_tags=["tag1", "tag2"]).save()
        observable = Observable(
            value='doman.com',
            type='hostname').save()

        observable.tag(["tag1"])
        neighbors = observable.neighbors()

        self.assertEqual(len(neighbors.vertices), 1)
        self.assertEqual(neighbors.vertices[entity.extended_id].json(), entity.json())
