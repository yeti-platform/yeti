import unittest

from core import database_arango, errors
from core.schemas.indicator import DiamondModel
from core.schemas.indicators.yara import Yara


class YaraIndicatorTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

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
        yara.validate_yara()

        self.assertEqual(yara.name, "test")
        self.assertEqual(yara.dependencies, ["dep"])

    def test_invalid_yara_rule(self):
        with self.assertRaises(errors.ObjectCreationError) as error:
            Yara(
                pattern='rule test { wooo: $a = "test" fooo: $a and dep }',
                location="any",
                diamond=DiamondModel.capability,
            ).save()

        self.assertIn("Unknown text wooo", str(error.exception))

    def test_fail_on_more_than_one_rule(self):
        with self.assertRaises(errors.ObjectCreationError) as error:
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

    def test_bulk_dependency_export(self):
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

        yara_rule2 = Yara(
            pattern="rule test2 { condition: true and dep2 }",
            location="any",
            diamond=DiamondModel.capability,
        )

        export = Yara.generate_yara_bundle([yara_rule, yara_rule2])
        self.assertEqual(
            export,
            "rule dep0 { condition: true }\n\n"
            "rule dep1 { condition: true and dep0 }\n\n"
            "rule dep2 { condition: true and dep1 }\n\n"
            "rule test { condition: true and dep2 and dep1 }\n\n"
            "rule test2 { condition: true and dep2 }\n\n",
        )

    def test_yara_dependency_creates_links(self):
        dep0 = Yara(
            pattern="rule dep0 { condition: true }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        dep1 = Yara(
            pattern="rule dep1 { condition: true and dep0 }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        dep2 = Yara(
            pattern="rule dep2 { condition: true and dep1 }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        yara_rule = Yara(
            pattern="rule test { condition: true and dep2 and dep1 }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        vertices, _, total = yara_rule.neighbors()
        self.assertEqual(total, 2)
        self.assertEqual(len(vertices), 2)

        self.assertEqual(vertices[dep1.extended_id].name, "dep1")
        self.assertEqual(vertices[dep2.extended_id].name, "dep2")

        vertices, _, total = dep1.neighbors()
        self.assertEqual(total, 3)
        self.assertEqual(len(vertices), 3)
        self.assertEqual(vertices[dep0.extended_id].name, "dep0")
        self.assertEqual(vertices[dep2.extended_id].name, "dep2")
        self.assertEqual(vertices[yara_rule.extended_id].name, "test")

    def test_yara_links_get_updated_when_deps_change(self):
        dep1 = Yara(
            pattern="rule dep1 { condition: true }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        dep2 = Yara(
            pattern="rule dep2 { condition: true }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        yara_rule = Yara(
            pattern="rule test { condition: dep2 and dep1 }",
            location="any",
            diamond=DiamondModel.capability,
        ).save()

        self.assertCountEqual(yara_rule.dependencies, ["dep2", "dep1"])

        vertices, _, total = yara_rule.neighbors()
        self.assertEqual(total, 2)
        self.assertEqual(len(vertices), 2)

        self.assertEqual(vertices[dep1.extended_id].name, "dep1")
        self.assertEqual(vertices[dep2.extended_id].name, "dep2")

        yara_rule.pattern = "rule test { condition: true and dep1 }"
        yara_rule = yara_rule.save()
        self.assertEqual(yara_rule.dependencies, ["dep1"])

        vertices, _, total = yara_rule.neighbors()
        self.assertEqual(total, 1)
        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[dep1.extended_id].name, "dep1")

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

    def test_overlay(self):
        rule_pattern = """
        rule test {
            meta:
                intact_meta = "foo"
                override_meta = "bar"
            strings:
                $a = "Ba"
            condition:
                $a
        }
        """
        rule = Yara(
            name="test",
            pattern=rule_pattern,
            location="any",
            diamond=DiamondModel.capability,
        ).save()
        rule.add_context("testOverlay", {"override_meta": "baz", "new_meta": "new"})

        rule.apply_overlays(["testOverlay"])
        # use regex to replace contiguous spaces and newlines by a single space
        import re

        new_pattern = re.sub(r"\s+", " ", rule.pattern)
        expected_pattern = re.sub(
            r"\s+",
            " ",
            """
        rule test {
            meta:
                intact_meta = "foo"
                override_meta = "baz"
                new_meta = "new"
            strings:
                $a = "Ba"
            condition:
                $a
        }
        """,
        )
        self.assertEqual(
            new_pattern.strip(),
            expected_pattern.strip(),
        )
