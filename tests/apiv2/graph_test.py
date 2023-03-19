from core import database_arango

from fastapi import FastAPI
from fastapi.testclient import TestClient
import unittest
from core.schemas.observable import Observable
from core.schemas.graph import Relationship
import datetime
from core.web import webapp

client = TestClient(webapp.app)

class ObservableTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        self.observable1 = Observable(
            value="tomchop.me",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        self.observable2 = Observable(
            value="127.0.0.1",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_get_neighbors(self):
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution")
        response = client.post(
            "/api/v2/graph/search",
            json={
                "source": self.observable1.extended_id,
                "link_type": "resolves",
                "hops": 1,
                "direction": "any",
                "include_original": False
                }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['vertices']), 1)
        neighbor = data['vertices'][self.observable2.extended_id]
        self.assertEqual(neighbor['value'], '127.0.0.1')
        self.assertEqual(neighbor['id'], self.observable2.id)

        edges = data['edges']
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]['source'], self.observable1.extended_id)
        self.assertEqual(edges[0]['target'], self.observable2.extended_id)
        self.assertEqual(edges[0]['type'], 'resolves')

    def test_add_link(self):
        response = client.post(
            "/api/v2/graph/add",
            json={
                "source": self.observable1.extended_id,
                "target": self.observable2.extended_id,
                "link_type": "resolves",
                "description": "DNS resolution"
                }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNotNone(data['id'])
        self.assertEqual(data['source'], self.observable1.extended_id)
        self.assertEqual(data['target'], self.observable2.extended_id)
        self.assertEqual(data['type'], 'resolves')
        self.assertEqual(data['description'], 'DNS resolution')

    def test_delete_link(self):
        """Tests that a relationship can be deleted."""
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)

        response = client.delete(
            f"/api/v2/graph/{self.relationship.id}"
        )
        self.assertEqual(response.status_code, 200)
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 0)
