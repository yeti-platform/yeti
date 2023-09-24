import datetime
import unittest

from core import database_arango
from core.schemas.entity import Entity, Malware, ThreatActor, Tool
from core.schemas.graph import Relationship
from core.schemas.observable import Observable


class EntityTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        self.ta1 = ThreatActor(name="APT123").save()
        self.malware1 = Malware(name="zeus").save()
        self.tool1 = Tool(name="mimikatz").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_create_entity(self) -> None:
        result = ThreatActor(name="APT0").save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "APT0")
        self.assertEqual(result.type, "threat-actor")

    def test_entity_get_correct_type(self) -> None:
        """Tests that entity returns the correct type."""
        assert self.ta1.id is not None
        result = Entity.get(self.ta1.id)
        assert result is not None
        self.assertIsNotNone(result)
        self.assertIsInstance(result, ThreatActor)
        self.assertEqual(result.type, 'threat-actor')

    def test_filter_entities_different_types(self) -> None:

        all_entities = list(Entity.list())
        threat_actor_entities = list(ThreatActor.list())
        tool_entities = list(Tool.list())
        malware_entities = list(Malware.list())

        self.assertEqual(len(all_entities), 3)

        self.assertEqual(len(threat_actor_entities), 1)
        self.assertEqual(len(tool_entities), 1)
        self.assertEqual(len(malware_entities), 1)

        self.assertEqual(threat_actor_entities[0].json(), self.ta1.json())
        self.assertEqual(tool_entities[0].json(), self.tool1.json())
        self.assertEqual(malware_entities[0].json(), self.malware1.json())

    def test_entity_with_tags(self):
        entity = ThreatActor(name="APT0", relevant_tags=["tag1", "tag2"]).save()
        observable = Observable(
            value='doman.com',
            type='hostname').save()

        observable.tag(["tag1"])
        vertices, edges, count = observable.neighbors()

        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[entity.extended_id].json(), entity.json())
        self.assertEqual(count, 1)

    def test_duplicate_name(self):
        """Tests that saving an entity with an existing name will return the existing entity."""
        ta = ThreatActor(name="APT123").save()
        self.assertEqual(ta.id, self.ta1.id)
