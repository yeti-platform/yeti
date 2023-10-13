import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import entity
from core.web import webapp

client = TestClient(webapp.app)


class EntityTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()
        self.entity1 = entity.ThreatActor(name="ta1").save()
        self.entity1.tag(['ta1-tag'])

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_get_entities(self):
        response = client.get("/api/v2/entities/")
        self.assertEqual(response.status_code, 200)

    def test_new_entity(self):
        response = client.post(
            "/api/v2/entities/",
            json={"entity": {"name": "ta2", "type": "threat-actor"}},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "ta2")
        self.assertEqual(data["type"], "threat-actor")

    def test_get_entity(self):
        response = client.get(f"/api/v2/entities/{self.entity1.id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "ta1")
        self.assertEqual(data["type"], "threat-actor")

    def test_search_entities(self):
        response = client.post(
            "/api/v2/entities/search", json={"name": "ta", "type": "threat-actor"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["entities"]), 1)
        self.assertEqual(data["entities"][0]["name"], "ta1")
        self.assertEqual(data["entities"][0]["type"], "threat-actor")

        # Check tags
        self.assertEqual(len(data["entities"][0]["tags"]), 1, data)
        self.assertIn("ta1-tag", data["entities"][0]["tags"])

    def test_new_entity_with_tag(self):
        response = client.post(
            "/api/v2/entities/",
            json={"entity": {"name": "ta2", "type": "threat-actor"}, "tags": ["hacker"]},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["name"], "ta2")
        self.assertIn("hacker", data["tags"], data["tags"])

    def test_tag_entity(self):
        """Tests that an entity gets tagged and tags are generated."""
        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [self.entity1.id], "tags": ["hacker"]},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["tagged"], 1)
        self.assertIn("hacker", data["tags"][self.entity1.extended_id], data)
