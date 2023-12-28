import logging
import sys
import unittest

from core import database_arango
from core.web import webapp
from fastapi.testclient import TestClient

client = TestClient(webapp.app)


class userTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.clear()

    def test_get_config(self) -> None:
        response = client.get("/api/v2/system/config")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("auth", data)
        self.assertIn("system", data)
