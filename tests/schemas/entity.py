import datetime
import unittest

from core import database_arango
from core.schemas import tag
from core.schemas.entity import (
    AttackPattern,
    Entity,
    Malware,
    ThreatActor,
    Tool,
    Vulnerability,
)
from core.schemas.observables import hostname


class EntityTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.ta1 = ThreatActor(name="APT123", aliases=["CrazyFrog"]).save()
        self.vuln1 = Vulnerability(name="CVE-2018-1337", title="elite exploit").save()
        self.malware1 = Malware(
            name="zeus", created=datetime.datetime(2020, 1, 1)
        ).save()
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

    def test_attack_pattern(self) -> None:
        result = AttackPattern(
            name="Abuse Elevation Control Mechanism",
            aliases=["T1548"],
            kill_chain_phases=["mitre-attack:Privilege Escalation"],
        ).save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "Abuse Elevation Control Mechanism")
        self.assertEqual(result.type, "attack-pattern")
        self.assertIn("T1548", result.aliases)

    def test_entity_dupe_name_type(self) -> None:
        oldm = Malware(name="APT123").save()
        ta = ThreatActor.find(name="APT123")
        m = Malware.find(name="APT123")
        self.assertEqual(ta.id, self.ta1.id)
        self.assertEqual(m.id, oldm.id)
        self.assertIsInstance(m, Malware)
        self.assertIsInstance(ta, ThreatActor)

    def test_list_entities(self) -> None:
        all_entities = list(Entity.list())
        threat_actor_entities = list(ThreatActor.list())
        tool_entities = list(Tool.list())
        malware_entities = list(Malware.list())

        self.assertEqual(len(all_entities), 4)

        self.assertEqual(len(threat_actor_entities), 1)
        self.assertEqual(len(tool_entities), 1)
        self.assertEqual(len(malware_entities), 1)

        self.assertEqual(threat_actor_entities[0], self.ta1)
        self.assertEqual(tool_entities[0], self.tool1)
        self.assertEqual(malware_entities[0], self.malware1)

    def test_filter_entities(self):
        entities, total = Entity.filter({"name": "APT123"})
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)
        self.assertEqual(entities[0], self.ta1)

    def test_filter_entities_regex(self):
        entities, total = Entity.filter({"name": "CVE", "title~": "Elite .xploit"})
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)
        self.assertEqual(entities[0], self.vuln1)

    def test_filter_entities_contain_lowercase(self):
        entities, total = Entity.filter({"name": "apt"})
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)
        self.assertEqual(entities[0], self.ta1)

    def test_filter_entities_by_regex(self):
        entities, total = Entity.filter({"name~": "APT[0-9]+"})
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)
        self.assertEqual(entities[0], self.ta1)

    def test_filter_entities_time(self):
        entities, total = Entity.filter({"created": "2020-01-01"})
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)
        self.assertEqual(entities[0], self.malware1)

        entities, total = Entity.filter({"created": "<2020-01-02"})
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)
        self.assertEqual(entities[0], self.malware1)

        entities, total = Entity.filter({"created": ">2020-01-02"})
        self.assertEqual(len(entities), 3)
        self.assertEqual(total, 3)
        self.assertNotIn(self.malware1, entities)

    def test_entity_with_tags(self):
        entity = ThreatActor(name="APT0").save()
        entity.tag(["tag1", "tag2"])
        observable = hostname.Hostname(value="doman.com").save()

        observable.tag(["tag1"])
        vertices, paths, count = observable.neighbors(
            graph="tagged", min_hops=2, max_hops=2
        )

        new_tag = tag.Tag.find(name="tag1")

        self.assertEqual(len(vertices), 2)
        self.assertEqual(vertices[entity.extended_id].extended_id, entity.extended_id)
        self.assertEqual(paths[0][0].source, observable.extended_id)
        self.assertEqual(paths[0][0].target, new_tag.extended_id)

        self.assertEqual(paths[0][1].source, entity.extended_id)
        self.assertEqual(paths[0][1].target, new_tag.extended_id)

        self.assertEqual(count, 1)

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

    def test_bad_cve_name(self):
        vulnerability = Vulnerability(name="1337-4242").save()
        self.assertEqual(Vulnerability.is_valid(vulnerability), False)

    def test_correct_cve_name(self):
        vulnerability = Vulnerability(name="CVE-1337-4242").save()
        self.assertEqual(Vulnerability.is_valid(vulnerability), True)
