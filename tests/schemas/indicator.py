import unittest

from core import database_arango
from core.schemas import indicator
from core.schemas.indicator import (
    DiamondModel,
    ForensicArtifact,
    Indicator,
    Query,
    Regex,
    # Yara,
)

from core.schemas.indicators.yara import Yara


class IndicatorTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

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

    def test_indicator_create(self) -> None:
        indicator_obj = indicator.create(
            name="regex1", type="regex", pattern="asd", diamond="capability"
        )
        self.assertIsInstance(indicator_obj, Regex)
        self.assertIsNone(indicator_obj.id)
        self.assertEqual(indicator_obj.name, "regex1")
        self.assertEqual(indicator_obj.type, "regex")
        self.assertEqual(indicator_obj.pattern, "asd")
        self.assertIsInstance(indicator_obj.diamond, DiamondModel)
        self.assertEqual(indicator_obj.diamond, DiamondModel.capability)

    def test_indicator_save(self) -> None:
        indicator_obj = indicator.save(
            name="regex1", type="regex", pattern="asd", diamond="capability"
        )
        self.assertIsInstance(indicator_obj, Regex)
        self.assertIsNotNone(indicator_obj.id)
        self.assertEqual(indicator_obj.name, "regex1")
        self.assertEqual(indicator_obj.type, "regex")
        self.assertEqual(indicator_obj.pattern, "asd")
        self.assertIsInstance(indicator_obj.diamond, DiamondModel)
        self.assertEqual(indicator_obj.diamond, DiamondModel.capability)

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
        self.assertEqual(result.matched_string, "BaaaadString")

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

    def test_yara_creation(self):
        yara = Yara(
            pattern='rule test { strings: $a = "test" condition: $a }',
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        self.assertIsNotNone(yara.id)
        self.assertIsNotNone(yara.created)
        self.assertEqual(yara.name, "test")
        self.assertEqual(yara.type, "yara")

    def test_yara_name_and_deps(self):
        yara = Yara(
            name="blah",
            pattern='rule test { strings: $a = "test" condition: $a and dep }',
            location="any",
            diamond=DiamondModel.capability,
        )

        self.assertEqual(yara.name, "test")
        self.assertEqual(yara.dependencies, ["dep"])

    def test_invalid_yara_rule(self):
        with self.assertRaises(ValueError) as error:
            Yara(
                pattern='rule test { wooo: $a = "test" fooo: $a and dep }',
                location="any",
                diamond=DiamondModel.capability,
            ).save()

        self.assertIn("Unknown text wooo", str(error.exception))

    def test_fail_on_more_than_one_rule(self):
        with self.assertRaises(ValueError) as error:
            Yara(
                pattern="rule test { condition: true } rule test2 { condition: true }",
                location="any",
                diamond=DiamondModel.capability,
            ).save()

        self.assertIn(
            "Only one Yara rule is allowed in the rule body.", str(error.exception)
        )

    def test_dependency_calculation(self):
        Yara(
            pattern="rule dep0 { condition: true }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        Yara(
            pattern="rule dep1 { condition: true and dep0 }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        Yara(
            pattern="rule dep2 { condition: true and dep1 }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        yara_rule = Yara(
            pattern="rule test { condition: true and dep2 and dep1 }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        deps = yara_rule.rule_with_dependencies()
        self.assertEqual(
            deps,
            (
                "rule dep0 { condition: true }\n\n"
                "rule dep1 { condition: true and dep0 }\n\n"
                "rule dep2 { condition: true and dep1 }\n\n"
                "rule test { condition: true and dep2 and dep1 }\n\n"
            ),
        )

    def test_yara_match(self):
        rule = Yara(
            name="yara1",
            pattern='rule test_rule { strings: $a = "Ba" condition: $a }',
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        result = rule.match("ThisIsAReallyBaaaadStringIsntIt")
        self.assertIsNotNone(result)
        self.assertEqual(result.matches[0].rule, "test_rule")
        self.assertEqual(result.matches[0].strings[0].identifier, "$a")
        self.assertEqual(result.matches[0].strings[0].instances[0].offset, 13)
        self.assertEqual(result.matches[0].strings[0].instances[0].matched_data, b"Ba")

        result = rule.match(b"ThisIsAReallyBaaaadStringIsntIt")
        self.assertIsNotNone(result)
        self.assertEqual(result.matches[0].rule, "test_rule")
        self.assertEqual(result.matches[0].strings[0].identifier, "$a")
        self.assertEqual(result.matches[0].strings[0].instances[0].offset, 13)
        self.assertEqual(result.matches[0].strings[0].instances[0].matched_data, b"Ba")
