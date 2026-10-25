import io
import logging
import unittest
import zipfile
from unittest import mock

from core import database_arango
from core.schemas.indicators.yara import Yara
from plugins.feeds.public import yaraify

SINGLE = """rule single_rule {
  meta:
    description = "one rule in its own file"
  strings:
    $a = "single"
  condition:
    $a
}
"""

# Two rules in one file, the second depending on the first.
MULTI = """rule base_rule {
  meta:
    description = "first of two"
  strings:
    $a = "base"
  condition:
    $a
}

rule derived_rule {
  meta:
    description = "second of two"
  condition:
    base_rule
}
"""

BROKEN = "rule broken_rule { condition: not_a_real_identifier( }"


def archive(files: dict[str, bytes]) -> mock.Mock:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zfile:
        for name, data in files.items():
            zfile.writestr(name, data)
    return mock.Mock(content=buffer.getvalue())


class YARAifyTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.feed = yaraify.YARAify(**yaraify.YARAify._defaults.copy())
        previous = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous)

    def run_feed(self, files: dict[str, bytes]) -> list[str]:
        with mock.patch.object(
            yaraify.YARAify, "_make_request", return_value=archive(files)
        ):
            with self.assertLogs(level=logging.INFO) as logs:
                self.feed.run()
        return logs.output

    def test_each_rule_of_a_multi_rule_file_is_its_own_indicator(self) -> None:
        self.run_feed({"multi.yar": MULTI.encode()})

        base, derived = Yara.find(name="base_rule"), Yara.find(name="derived_rule")
        assert base is not None and derived is not None
        self.assertNotIn("derived_rule", base.pattern)
        self.assertNotIn("rule base_rule", derived.pattern)
        self.assertEqual(derived.dependencies, ["base_rule"])

    def test_rule_descriptions_are_kept(self) -> None:
        self.run_feed({"single.yar": SINGLE.encode(), "multi.yar": MULTI.encode()})

        for name, description in (
            ("single_rule", "one rule in its own file"),
            ("base_rule", "first of two"),
            ("derived_rule", "second of two"),
        ):
            rule = Yara.find(name=name)
            assert rule is not None, name
            self.assertEqual(rule.description, description)

    def test_bad_files_are_skipped_and_the_rest_imported(self) -> None:
        output = "\n".join(
            self.run_feed(
                {
                    "broken.yar": BROKEN.encode(),
                    "not-utf8.yar": b'rule latin { strings: $a = "\xe9" condition: $a }',
                    "single.yar": SINGLE.encode(),
                    "README.txt": b"not a rule file",
                }
            )
        )

        self.assertIsNotNone(Yara.find(name="single_rule"))
        self.assertIn("could not import broken.yar", output)
        self.assertIn("could not import not-utf8.yar", output)
        self.assertIn("imported 1 rule files, 2 could not be imported", output)
        self.assertNotIn("README.txt", output)
