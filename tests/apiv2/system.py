from core import database_arango

from fastapi.testclient import TestClient
import unittest

from core.web import webapp

client = TestClient(webapp.app)


class userTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()

    def test_get_config(self) -> None:
        response = client.get("/api/v2/system/config")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("auth", data)
        self.assertIn("arangodb", data)
        self.assertIn("redis", data)
        self.assertIn("proxy", data)
        self.assertIn("logging", data)
