from core import database_arango

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

    def test_node_deletion_affects_link(self) -> None:
        """Tests that deleting a node also deletes assocaited relationships."""
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)

        self.observable1.delete()
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 0)

    def test_no_neighbors(self):
        """Tests that a node with no neighbors returns an empty list."""
        neighbors = self.observable1.neighbors()
        self.assertEqual(len(neighbors.vertices), 0)
