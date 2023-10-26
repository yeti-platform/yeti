import unittest

from core import database_arango
from core.schemas.entity import Entity, Malware, ThreatActor, Tool, AttackPattern
from core.schemas.observables import hostname
from core.schemas import tag


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
        self.assertEqual(result.type, "threat-actor")

    def test_filter_entities_different_types(self) -> None:

        all_entities = list(Entity.list())
        threat_actor_entities = list(ThreatActor.list())
        tool_entities = list(Tool.list())
        malware_entities = list(Malware.list())

        self.assertEqual(len(all_entities), 3)

        self.assertEqual(len(threat_actor_entities), 1)
        self.assertEqual(len(tool_entities), 1)
        self.assertEqual(len(malware_entities), 1)

        self.assertEqual(
            threat_actor_entities[0].model_dump_json(), self.ta1.model_dump_json()
        )
        self.assertEqual(
            tool_entities[0].model_dump_json(), self.tool1.model_dump_json()
        )
        self.assertEqual(
            malware_entities[0].model_dump_json(), self.malware1.model_dump_json()
        )

    def test_entity_with_tags(self):
        entity = ThreatActor(name="APT0").save()
        entity.tag(['tag1', 'tag2'])
        observable = hostname.Hostname(value="doman.com").save()

        observable.tag(["tag1"])
        vertices, edges, count = observable.neighbors(
            graph='tagged',
            hops=2
            )

        new_tag = tag.Tag.find(name="tag1")

        self.assertEqual(len(vertices), 2)
        self.assertEqual(
            vertices[entity.extended_id].extended_id, entity.extended_id
        )
        self.assertEqual(edges[0].source, observable.extended_id)
        self.assertEqual(edges[0].target, new_tag.extended_id)
        self.assertEqual(edges[1].source, entity.extended_id)
        self.assertEqual(edges[1].target, new_tag.extended_id)

        self.assertEqual(count, 2)

    def test_duplicate_name(self):
        """Tests that saving an entity with an existing name will return the existing entity."""
        ta = ThreatActor(name="APT123").save()
        self.assertEqual(ta.id, self.ta1.id)

    def test_entity_duplicate_name(self):
        """Tests that two entities of different types can have the same name."""
        psexec_tool = Tool(name="psexec").save()
        psexec_ap = AttackPattern(name="psexec").save()
        self.assertNotEqual(psexec_tool.id, psexec_ap.id)
        self.assertEqual(psexec_tool.type, "tool")
        self.assertEqual(psexec_ap.type, "attack-pattern")

    def test_no_empty_name(self):
        """Tests that an entity with an empty name cannot be saved."""
        with self.assertRaises(ValueError):
            ThreatActor(name="").save()
