import unittest

from core import database_arango
from core.schemas.indicator import (
    DiamondModel,
    ForensicArtifact,
    Indicator,
    Query,
    Regex,
    Suricata,
)


class IndicatorTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_create_indicator(self) -> None:
        result = Regex(
            name="regex1",
            pattern="asd",
            location="any",
            diamond=DiamondModel.capability,
        ).save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "regex1")
        self.assertEqual(result.type, "regex")

    def test_filter_entities_different_types(self) -> None:
        regex = Regex(
            name="regex1",
            pattern="asd",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        all_entities = list(Indicator.list())
        regex_entities = list(Regex.list())

        self.assertEqual(len(all_entities), 1)
        self.assertEqual(len(regex_entities), 1)
        self.assertEqual(regex_entities[0].model_dump_json(), regex.model_dump_json())

    def test_create_indicator_same_name_diff_types(self) -> None:
        regex = Regex(
            name="persistence1",
            pattern="asd",
            location="any",
            diamond=DiamondModel.capability,
        ).save()
        regex2 = Query(
            name="persistence1",
            pattern="asd",
            location="any",
            query_type="query",
            diamond=DiamondModel.capability,
        ).save()
        self.assertNotEqual(regex.id, regex2.id)
        r = Regex.find(name="persistence1")
        q = Query.find(name="persistence1")
        self.assertNotEqual(r.id, q.id)

    def test_regex_match(self) -> None:
        regex = Regex(
            name="regex1",
            pattern="Ba+dString",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        result = regex.match("ThisIsAReallyBaaaadStringIsntIt")
        assert result is not None
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "regex1")
        self.assertEqual(result.match, "BaaaadString")

    def test_regex_nomatch(self) -> None:
        regex = Regex(
            name="regex1",
            pattern="Blah",
            location="any",
            diamond=DiamondModel.capability,
        ).save()
        result = regex.match("ThisIsAReallyBaaaadStringIsntIt")
        self.assertIsNone(result)

    def test_forensics_artifacts_indicator_extraction_file(self) -> None:
        pattern = """
        doc: random description
        name: ForensicArtifact1
        sources:
        - attributes:
            paths:
                - /etc/shadow
                - /etc/random/*
                - '%%users.homedir%%/random'
                - '%%users.homedir%%/.dropbox/instance*/sync_history.db'
                - '%%environ_systemdrive%%\$Extend\$UsnJrnl'
          supported_os:
            - Darwin
            - Linux
          type: FILE
        supported_os:
        - Darwin
        - Linux"""

        artifacts = ForensicArtifact.from_yaml_string(pattern)
        db_artifact = artifacts[0]
        self.assertIsNotNone(db_artifact.id)
        self.assertIsNotNone(db_artifact.created)
        self.assertEqual(db_artifact.name, "ForensicArtifact1")
        self.assertEqual(db_artifact.supported_os, ["Darwin", "Linux"])

        indicators = db_artifact.save_indicators(create_links=True)
        vertices, _, total = db_artifact.neighbors()

        self.assertEqual(total, 5)
        self.assertEqual(len(vertices), 5)

        self.assertEqual(vertices[indicators[0].extended_id].name, "/etc/shadow")
        self.assertEqual(vertices[indicators[0].extended_id].pattern, r"/etc/shadow")
        self.assertEqual(vertices[indicators[0].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[0].extended_id].location, "filesystem")

        self.assertEqual(vertices[indicators[1].extended_id].name, "/etc/random/*")
        self.assertEqual(vertices[indicators[1].extended_id].pattern, r"/etc/random/.*")
        self.assertEqual(vertices[indicators[1].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[1].extended_id].location, "filesystem")

        self.assertEqual(
            vertices[indicators[2].extended_id].name, "%%users.homedir%%/random"
        )
        self.assertEqual(vertices[indicators[2].extended_id].pattern, r".*/random")
        self.assertEqual(vertices[indicators[2].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[2].extended_id].location, "filesystem")

        self.assertEqual(
            vertices[indicators[3].extended_id].name,
            "%%users.homedir%%/.dropbox/instance*/sync_history.db",
        )
        self.assertEqual(
            vertices[indicators[3].extended_id].pattern,
            r".*/\.dropbox/instance.*/sync_history\.db",
        )
        self.assertEqual(vertices[indicators[3].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[3].extended_id].location, "filesystem")

        self.assertEqual(
            vertices[indicators[4].extended_id].name,
            "%%environ_systemdrive%%\\$Extend\\$UsnJrnl",
        )
        self.assertEqual(
            vertices[indicators[4].extended_id].pattern,
            r".*[\|/]\$Extend[\|/]\$UsnJrnl",
        )
        self.assertEqual(vertices[indicators[4].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[4].extended_id].location, "filesystem")

    def test_forensics_artifacts_indicator_extraction_registry(self) -> None:
        pattern = """doc: asd
name: WindowsRunKeys
sources:
- attributes:
    keys:
    - HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*
    - HKEY_USERS\\%%users.sid%%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*
    - HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\amdi2c
  type: REGISTRY_KEY
supported_os:
- Windows"""

        artifacts = ForensicArtifact.from_yaml_string(pattern)
        db_artifact = artifacts[0]
        self.assertIsNotNone(db_artifact.id)
        self.assertIsNotNone(db_artifact.created)
        self.assertEqual(db_artifact.name, "WindowsRunKeys")
        self.assertEqual(db_artifact.supported_os, ["Windows"])

        indicators = db_artifact.save_indicators(create_links=True)
        vertices, _, total = db_artifact.neighbors()

        self.assertEqual(total, 3)
        self.assertEqual(len(vertices), 3)

        self.assertEqual(
            vertices[indicators[0].extended_id].name,
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        )
        self.assertEqual(
            vertices[indicators[0].extended_id].pattern,
            r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        self.assertEqual(vertices[indicators[0].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[0].extended_id].location, "registry")

        self.assertEqual(
            vertices[indicators[1].extended_id].name,
            "HKEY_USERS\\%%users.sid%%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        )
        self.assertEqual(
            vertices[indicators[1].extended_id].pattern,
            r"(HKEY_USERS\\.*|HKEY_CURRENT_USER)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        self.assertEqual(vertices[indicators[1].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[1].extended_id].location, "registry")

        self.assertEqual(
            vertices[indicators[2].extended_id].name,
            "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\amdi2c",
        )
        self.assertEqual(
            vertices[indicators[2].extended_id].pattern,
            r"(CurrentControlSet|ControlSet[0-9]+)\\Services\\amdi2c",
        )
        self.assertEqual(vertices[indicators[2].extended_id].type, "regex")
        self.assertEqual(vertices[indicators[2].extended_id].location, "registry")

    def test_forensic_artifacts_parent_extraction(self):
        pattern = """
name: KasperskyCaretoIndicators
doc: Kaspersky Careto indicators of compromise (IOCs).
sources:
- type: ARTIFACT_GROUP
  attributes:
    names:
    - Artifact2
    - Artifact3
---
name: Artifact2
doc: random description
sources:
- type: FILE
  attributes:
    paths:
    - blah
---
name: Artifact3
doc: random description
sources:
- type: FILE
  attributes:
    paths:
    - blah3
"""

        artifacts = ForensicArtifact.from_yaml_string(pattern, update_parents=True)
        self.assertEqual(len(artifacts), 3)

        vertices, _, total = artifacts[0].neighbors()
        self.assertEqual(total, 2)
        self.assertEqual(len(vertices), 2)

        self.assertEqual(vertices[artifacts[1].extended_id].name, "Artifact2")
        self.assertEqual(vertices[artifacts[2].extended_id].name, "Artifact3")

    def test_suricata_rule(self):
        rule = Suricata(
            name="rule1",
            pattern='alert tcp any any -> any any (msg:"test"; content:"test"; sid:1;)',
            diamond=DiamondModel.capability,
        ).save()
        self.assertIsNotNone(rule.id)
        self.assertIsNotNone(rule.created)
        self.assertEqual(rule.name, "rule1")
        self.assertEqual(rule.type, "suricata")
