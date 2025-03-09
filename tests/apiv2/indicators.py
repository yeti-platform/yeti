import json
import logging
import sys
import time
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import indicator
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class IndicatorTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        # database_arango.db.create_views(testing=True)

        user = UserSensitive(username="test", password="test", enabled=True).save()
        apikey = user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}
        self.indicator1 = indicator.Regex(
            name="hex",
            pattern="[0-9a-f]",
            location="filesystem",
            diamond=indicator.DiamondModel.capability,
        ).save()
        self.indicator1.tag(["hextag"])
        self.indicator2 = indicator.Regex(
            name="localhost",
            pattern="127.0.0.1",
            location="network",
            diamond=indicator.DiamondModel.infrastructure,
        ).save()

        # allow for views to catch up
        time.sleep(1)

    def test_new_indicator(self):
        indicator_dict = {
            "name": "otherRegex",
            "type": "regex",
            "pattern": "[0-9a-f]",
            "location": "filesystem",
            "diamond": "capability",
        }
        response = client.post(
            "/api/v2/indicators/",
            json={"indicator": indicator_dict},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "otherRegex")
        self.assertEqual(data["type"], "regex")

    def test_add_context(self):
        response = client.post(
            f"/api/v2/indicators/{self.indicator1.id}/context",
            json={"source": "testSource", "context": {"test": "test"}},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["context"], [{"test": "test", "source": "testSource"}])

    def test_replace_context(self):
        self.indicator1.add_context("testSource", {"test": "test"})
        response = client.put(
            f"/api/v2/indicators/{self.indicator1.id}/context",
            json={"context": [{"test2": "test2", "source": "blahSource"}]},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["context"], [{"test2": "test2", "source": "blahSource"}])

    def test_delete_context(self):
        self.indicator1.add_context("testSource", {"test": "test"})
        response = client.post(
            f"/api/v2/indicators/{self.indicator1.id}/context/delete",
            json={"source": "testSource", "context": {"test": "test"}},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["context"], [])

    def test_get_indicator(self):
        response = client.get(f"/api/v2/indicators/{self.indicator1.id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["name"], "hex")
        self.assertEqual(data["type"], "regex")

    def test_search_indicators(self):
        response = client.post(
            "/api/v2/indicators/search", json={"query": {"name": "he"}, "type": "regex"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["indicators"]), 1)
        self.assertEqual(data["indicators"][0]["name"], "hex")
        self.assertEqual(data["indicators"][0]["type"], "regex")

        # check tag
        self.assertEqual(len(data["indicators"][0]["tags"]), 1)
        self.assertIn("hextag", data["indicators"][0]["tags"])

    def test_search_indicators_tagged(self):
        response = client.post(
            "/api/v2/indicators/search",
            json={"query": {"name": "", "tags": ["hextag"]}, "type": "regex"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["indicators"]), 1)
        self.assertEqual(data["indicators"][0]["name"], "hex")
        self.assertEqual(data["indicators"][0]["type"], "regex")

    def test_search_indicators_subfields(self):
        response = client.post(
            "/api/v2/indicators/search",
            json={"query": {"location": "filesystem"}, "type": "regex"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["indicators"]), 1)
        self.assertEqual(data["indicators"][0]["name"], "hex")
        self.assertEqual(data["indicators"][0]["type"], "regex")

    def test_search_indicators_by_alias(self):
        indicator.Query(
            name="query1",
            pattern="SELECT * FROM table",
            location="database",
            target_systems=["mysql"],
            query_type="sql",
            diamond=indicator.DiamondModel.capability,
        ).save()
        time.sleep(1)
        response = client.post(
            "/api/v2/indicators/search",
            json={
                "query": {"name": "mys"},
                "type": "query",
                "filter_aliases": [["target_systems", "list"]],
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["indicators"]), 1)
        self.assertEqual(data["indicators"][0]["name"], "query1")

    def test_delete_indicator(self):
        response = client.delete(f"/api/v2/indicators/{self.indicator1.id}")
        self.assertEqual(response.status_code, 200)
        response = client.get(f"/api/v2/indicators/{self.indicator1.id}")
        self.assertEqual(response.status_code, 404)

    def test_patch_indicator(self):
        self.indicator1.pattern = "blah"
        dump = self.indicator1.model_dump_json()
        response = client.patch(
            f"/api/v2/indicators/{self.indicator1.id}",
            json={"indicator": json.loads(dump)},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["pattern"], "blah")
        self.assertEqual(data["type"], "regex")

    def test_bad_regex(self):
        indicator_dict = {
            "name": "badRegex",
            "type": "regex",
            "pattern": "[0-9a-f",
            "location": "filesystem",
            "diamond": "capability",
        }
        response = client.post(
            "/api/v2/indicators/",
            json={"indicator": indicator_dict},
        )
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertIn("Value error, Invalid regex pattern", data["detail"][0]["msg"])

    def test_bad_yara(self):
        indicator_dict = {
            "type": "yara",
            "pattern": "rule test {",
            "location": "filesystem",
            "diamond": "capability",
        }
        response = client.post(
            "/api/v2/indicators/",
            json={"indicator": indicator_dict},
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn(
            "No valid Yara rules found in the rule body", data["detail"]["description"]
        )

    def test_bad_yara_graceful_failure(self):
        indicator_dict = {
            "type": "yara",
            "pattern": 'rule test { strings: $a = "test" condition: $a and MissingRule and OtherMissingRule }',
            "location": "filesystem",
            "diamond": "victim",
        }
        response = client.post(
            "/api/v2/indicators/",
            json={"indicator": indicator_dict},
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertCountEqual(
            data["detail"]["meta"]["missing_dependencies"],
            ["MissingRule", "OtherMissingRule"],
        )
        self.assertEqual(
            data["detail"]["description"],
            "Missing dependency when creating Yara rule",
        )

    def test_new_yara(self):
        indicator_dict = {
            "type": "yara",
            "pattern": 'rule test { strings: $a = "test" condition: $a }',
            "location": "filesystem",
            "diamond": "capability",
        }
        response = client.post(
            "/api/v2/indicators/",
            json={"indicator": indicator_dict},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "test")
        self.assertEqual(data["type"], "yara")
