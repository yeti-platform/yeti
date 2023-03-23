import datetime
import unittest

from core import database_arango
from core.schemas.indicator import Indicator, Regex
from core.schemas.observable import Observable


class IndicatorTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_create_entity(self) -> None:
        result = Regex(name="regex1", pattern="asd", location="any").save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "regex1")
        self.assertEqual(result.type, "regex")

    def test_filter_entities_different_types(self) -> None:
        regex = Regex(name="regex1", pattern="asd", location="any").save()

        all_entities = list(Indicator.list())
        regex_entities = list(Regex.list())

        self.assertEqual(len(all_entities), 1)
        self.assertEqual(len(regex_entities), 1)
        self.assertEqual(regex_entities[0].json(), regex.json())

    def test_regex_match(self) -> None:
        regex = Regex(name="regex1", pattern="Ba+dString", location="any").save()

        result = regex.match('ThisIsAReallyBaaaadStringIsntIt')
        assert result is not None
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "regex1")
        self.assertEqual(result.match, "BaaaadString")

    def test_regex_nomatch(self) -> None:
        regex = Regex(name="regex1", pattern="Blah", location="any").save()
        result = regex.match('ThisIsAReallyBaaaadStringIsntIt')
        self.assertIsNone(result)
