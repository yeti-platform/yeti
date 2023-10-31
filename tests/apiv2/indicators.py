import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import indicator
from core.web import webapp

client = TestClient(webapp.app)


class IndicatorTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()
        self.indicator1 = indicator.Regex(
            name="hex",
            pattern="[0-9a-f]",
            location='filesystem',
            diamond=indicator.DiamondModel.capability
            ).save()
        self.indicator2 = indicator.Regex(
            name="localhost",
            pattern="127.0.0.1",
            location='network',
            diamond=indicator.DiamondModel.infrastructure
            ).save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_get_indicators(self):
        response = client.get("/api/v2/indicators/")
        self.assertEqual(response.status_code, 200)

    def test_new_indicator(self):
        indicator_dict = {
            "name": "otherRegex",
            "type": "regex",
            "pattern": "[0-9a-f]",
            "location": "filesystem",
            "diamond": "capability"
        }
        response = client.post(
            "/api/v2/indicators/",
            json={"indicator": indicator_dict},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "otherRegex")
        self.assertEqual(data["type"], "regex")

    def test_get_indicator(self):
        response = client.get(f"/api/v2/indicators/{self.indicator1.id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "hex")
        self.assertEqual(data["type"], "regex")

    def test_sarch_indicators(self):
        response = client.post(
            "/api/v2/indicators/search", json={"query": {"name": "he"}, "type": "regex"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["indicators"]), 1)
        self.assertEqual(data["indicators"][0]["name"], "hex")
        self.assertEqual(data["indicators"][0]["type"], "regex")

    def test_search_indicators_subfields(self):
        response = client.post(
            "/api/v2/indicators/search", json={"query": {"location": "filesystem"}, "type": "regex"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["indicators"]), 1)
        self.assertEqual(data["indicators"][0]["name"], "hex")
        self.assertEqual(data["indicators"][0]["type"], "regex")
