from core import database_arango
import datetime

from fastapi.testclient import TestClient
import unittest

from core.schemas import entity
from core.web import webapp

client = TestClient(webapp.app)

class ObservableTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        self.entity1 = entity.ThreatActor(name="ta1").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_get_entities(self):
        response = client.get("/api/v2/entities/")
        self.assertEqual(response.status_code, 200)

    def test_new_entity(self):
        response = client.post(
            "/api/v2/entities/",
            json={"entity": {"name": "ta2", "type": "threat-actor"}})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['name'], "ta2")
        self.assertEqual(data['type'], "threat-actor")

    def test_get_entity(self):
        response = client.get(f"/api/v2/entities/{self.entity1.id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['name'], "ta1")
        self.assertEqual(data['type'], "threat-actor")
