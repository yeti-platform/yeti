from core import database_arango

from fastapi import FastAPI
from fastapi.testclient import TestClient
import unittest

from core.web import webapp

client = TestClient(webapp.app)

class tagTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_create_tag(self):
        response = client.post("/api/v2/tags/", json={"name": "tag1"})
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(data['id'])

        client.get(f"/api/v2/tags/{data['id']}")
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['name'], "tag1")

    def test_update_tag(self):
        response = client.post("/api/v2/tags/", json={"name": "tag1"})
        data1 = response.json()
        self.assertIsNotNone(data1['id'])
        self.assertEqual(response.status_code, 200)

        response = client.put(
            f"/api/v2/tags/{data1['id']}",
            json={"name": "tag111", "default_expiration_days": 10})
        self.assertEqual(response.status_code, 200)
        data2 = response.json()
        self.assertEqual(data1["id"], data2["id"])
        self.assertEqual(data2['name'], "tag111")
        self.assertEqual(data2['default_expiration'], 864000)  # 10 days

    def test_tag_search(self):
        response = client.post(
            "/api/v2/tags/",
            json={"name": "tag1-test"})
        self.assertEqual(response.status_code, 200)
        response = client.post(
            "/api/v2/tags/",
            json={"name": "tag2-test"})
        self.assertEqual(response.status_code, 200)

        response = client.post(
            "/api/v2/tags/search",
            json={"name": "tag1", "page": 0, "count": 10})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'tag1-test')

        response = client.post(
            "/api/v2/tags/search",
            json={"name": "tag", "page": 0, "count": 10})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 2)
