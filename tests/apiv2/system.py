import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class userTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

    def test_get_config(self) -> None:
        response = client.get("/api/v2/system/config")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("auth", data)
        self.assertIn("system", data)
        self.assertIn("rbac_enabled", data)


class SystemTypesTest(unittest.TestCase):
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

    def test_get_types(self) -> None:
        response = client.get("/api/v2/system/types")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("observables", data)
        self.assertIn("entities", data)
        self.assertIn("indicators", data)
        self.assertIn("dfiq", data)

        observable_types = {entry["type"] for entry in data["observables"]}
        # These are the exact types issue #1260 reported missing from the
        # frontend's hardcoded dropdown.
        self.assertTrue(
            {"ja3", "jarm", "mutex", "named_pipe", "package"} <= observable_types
        )
        # The family's own base type/aliases must not leak in as entries.
        self.assertNotIn("observable", observable_types)
        self.assertNotIn("observables", observable_types)

        indicator_types = {entry["type"] for entry in data["indicators"]}
        self.assertEqual(
            indicator_types,
            {"forensicartifact", "regex", "query", "yara", "suricata", "sigma"},
        )

        dfiq_types = {entry["type"] for entry in data["dfiq"]}
        self.assertEqual(dfiq_types, {"scenario", "facet", "question"})
        self.assertNotIn("dfiq", dfiq_types)

        # Every entry carries a non-empty label.
        for family in ("observables", "entities", "indicators", "dfiq"):
            for entry in data[family]:
                self.assertTrue(entry["label"])

    def test_get_types_requires_auth(self) -> None:
        client.headers = {}
        response = client.get("/api/v2/system/types")
        self.assertEqual(response.status_code, 401, response.json())
