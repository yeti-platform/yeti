import logging
import sys
import time
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import dfiq, entity, indicator, observable
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class searchTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

        user = UserSensitive(username="test", password="test", enabled=True).save()
        apikey = user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

        entity.Malware(
            name="test_malware",
            description="Test malware entity",
            type="malware",
        ).save()
        m2 = entity.Malware(
            name="tagged_malware",
            description="malware entity 2",
            type="malware",
        ).save()
        m2.tag("tagged")
        m2.tag("global")

        r = indicator.Regex(
            name="test_regex_global",
            description="Test regex indicator",
            type="regex",
            pattern="^test.*",
            diamond="victim",
        ).save()
        o = observable.Hostname(
            description="Test hostname observable",
            type="hostname",
            value="test.tomchop.me",
        ).save()
        dfiq.DFIQScenario(
            name="test_dfiq",
            description="Test DFIQ",
            dfiq_tags=["tagged", "global"],
            dfiq_version="1.0.1",
            dfiq_yaml="name: test_dfiq\nversion: 1.0.1\ndescription: Test DFIQ",
        ).save()
        r.tag("tagged")
        o.tag(["tagged", "global"])
        time.sleep(5)

    def test_search_name_or_value(self) -> None:
        """Test global search by name or value."""
        params = {"query": {"name": "test"}, "filter_aliases": [["value", "text"]]}
        response = client.post("/api/v2/search", json=params)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("results", data)
        self.assertEqual(len(data["results"]), 4, data)
        names_or_values = [
            r["name"] if "name" in r else r["value"] for r in data["results"]
        ]
        self.assertCountEqual(
            names_or_values,
            ["test_malware", "test_regex_global", "test.tomchop.me", "test_dfiq"],
            data,
        )

    def test_search_tag(self) -> None:
        """Test global search by tag."""
        params = {
            "query": {"tags": ["tagged"]},
        }
        response = client.post("/api/v2/search", json=params)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("results", data)
        self.assertEqual(len(data["results"]), 3, data)
        names_or_values = [
            r["name"] if "name" in r else r["value"] for r in data["results"]
        ]
        self.assertCountEqual(
            names_or_values,
            [
                "test_regex_global",
                "test.tomchop.me",
                "tagged_malware",
            ],
            data,
        )

    def test_search_more_fields(self) -> None:
        """Test global search with more fields."""
        params = {
            "query": {"name": "global"},
            "filter_aliases": [
                ["value", "text"],
                ["tags", ""],
                ["dfiq_tags", "list"],
            ],
        }
        response = client.post("/api/v2/search", json=params)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("results", data)
        self.assertEqual(len(data["results"]), 4, data)
        names_or_values = [
            r["name"] if "name" in r else r["value"] for r in data["results"]
        ]
        self.assertCountEqual(
            names_or_values,
            ["test_regex_global", "test.tomchop.me", "tagged_malware", "test_dfiq"],
            data,
        )
