import logging
import sys
import unittest

from core import database_arango
from core.schemas.tag import Tag
from core.schemas.user import UserSensitive
from core.web import webapp
from fastapi.testclient import TestClient

client = TestClient(webapp.app)


class tagTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}
        self.tag = Tag(name="tag1").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_create_tag(self):
        response = client.post("/api/v2/tags/", json={"name": "tag2"})
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(data["id"])

        client.get(f"/api/v2/tags/{data['id']}")
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["name"], "tag2")

    def test_update_tag(self):
        response = client.put(
            f"/api/v2/tags/{self.tag.id}",
            json={"name": "tag111", "default_expiration": 'P10D'},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(self.tag.id, data["id"])
        self.assertEqual(data["name"], "tag111")
        self.assertEqual(data["default_expiration"], "P10D")  # 10 daysin ISO 8601

    def test_tag_search(self):
        response = client.post("/api/v2/tags/", json={"name": "tag2-test"})
        self.assertEqual(response.status_code, 200)

        response = client.post(
            "/api/v2/tags/search", json={"name": "tag1", "page": 0, "count": 10}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["tags"]), 1)
        self.assertEqual(data["tags"][0]["name"], "tag1")
        self.assertEqual(data["total"], 1)

        response = client.post(
            "/api/v2/tags/search", json={"name": "tag", "page": 0, "count": 10}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 2)

    def test_tag_delete(self):
        response = client.delete(f"/api/v2/tags/{self.tag.id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(list(Tag.list())), 0)

    def test_tag_merge(self):
        Tag(name="tag2", replaces=["tag3"]).save()
        response = client.post(
            "/api/v2/tags/merge",
            json={"merge": ["tag2"], "merge_into": "tag1", "permanent": True},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["merged"], 1)
        self.assertEqual(sorted(data["into"]["replaces"]), ["tag2", "tag3"])

    def test_tag_merge_into_itself(self):
        response = client.post(
            "/api/v2/tags/merge",
            json={"merge": ["tag1"], "merge_into": "tag1", "permanent": True},
        )
        data = response.json()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(data["detail"], "Cannot merge a tag into itself")
