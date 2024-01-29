import unittest

from core import database_arango
from core.schemas.entity import Malware
from core.schemas.graph import Relationship
from core.schemas.observables import hostname, ipv4
from core.web import webapp
from fastapi.testclient import TestClient

client = TestClient(webapp.app)


class ObservableTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.observable1 = hostname.Hostname(value="tomchop.me").save()
        self.observable2 = ipv4.IPv4(value="127.0.0.1").save()
        self.observable3 = ipv4.IPv4(value="8.8.8.8").save()
        self.entity1 = Malware(name="plugx").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_node_deletion_affects_link(self) -> None:
        """Tests that deleting a node also deletes assocaited relationships."""
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution"
        )
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)

        self.observable1.delete()
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 0)

    def test_observable_to_observable_link(self) -> None:
        """Tests that a link between two observables can be created."""
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution"
        )
        self.assertEqual(self.relationship.source, self.observable1.extended_id)
        self.assertEqual(self.relationship.target, self.observable2.extended_id)
        self.assertEqual(self.relationship.type, "resolves")
        self.assertEqual(self.relationship.description, "DNS resolution")

        vertices, paths, count = self.observable1.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(count, 1)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], [self.relationship])
        self.assertEqual(vertices[self.observable2.extended_id].value, "127.0.0.1")

    def test_observable_to_entity_link(self) -> None:
        """Tests that a link between an observable and an entity can be created."""
        self.relationship = self.observable1.link_to(
            self.entity1, "network-traffic", "Sends network traffic"
        )
        self.assertEqual(self.relationship.source, self.observable1.extended_id)
        self.assertEqual(self.relationship.target, self.entity1.extended_id)
        self.assertEqual(self.relationship.type, "network-traffic")
        self.assertEqual(self.relationship.description, "Sends network traffic")

        vertices, edges, count = self.entity1.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(count, 1)
        self.assertEqual(vertices[self.observable1.extended_id].value, "tomchop.me")

    def test_no_neighbors(self):
        """Tests that a node with no neighbors returns an empty list."""
        vertices, edges, count = self.observable1.neighbors()
        self.assertEqual(len(vertices), 0)
        self.assertEqual(count, 0)

    def test_same_link_diff_objects(self):
        """Tests that an object can have identical links to different objects."""
        self.entity1.link_to(self.observable2, "a", "b")
        self.entity1.link_to(self.observable1, "a", "b")

        # Entity has 2 links to observables
        vertices, edges, count = self.entity1.neighbors()
        self.assertEqual(len(vertices), 2)
        self.assertEqual(count, 2)
        self.assertEqual(vertices[self.observable1.extended_id].value, "tomchop.me")
        self.assertEqual(vertices[self.observable2.extended_id].value, "127.0.0.1")

        # Observable has 1 link to entity1
        vertices, edges, count = self.observable1.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(count, 1)
        self.assertEqual(vertices[self.entity1.extended_id].name, "plugx")

    def test_neighbors_go_both_ways(self):
        """Tests that a link between two nodes is bidirectional."""
        self.observable1.link_to(self.observable2, "a", "b")

        # Observable1 has 1 link to observable2
        vertices, edges, count = self.observable1.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(count, 1)

        vertices, edges, count = self.observable2.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(count, 1)

    def test_neighbors_link_types(self):
        """Tests that a link between two nodes is bidirectional."""
        self.observable1.link_to(self.observable2, "a", "a")
        self.observable1.link_to(self.observable2, "b", "b")
        self.observable1.link_to(self.observable3, "c", "c")

        vertices, edges, edge_count = self.observable1.neighbors(link_types=["a"])
        self.assertEqual(len(vertices), 1)
        self.assertEqual(edge_count, 1)

        vertices, edges, edge_count = self.observable1.neighbors()
        self.assertEqual(len(vertices), 2)
        self.assertEqual(edge_count, 3)

    def test_neighbors_target_types(self):
        """Tests that a link between two nodes is bidirectional."""
        self.observable1.link_to(self.observable2, "a", "a")
        self.observable1.link_to(self.observable3, "c", "c")

        vertices, edges, edge_count = self.observable1.neighbors(target_types=["ipv4"])
        self.assertEqual(len(vertices), 2)
        self.assertEqual(edge_count, 2)

        vertices, edges, edge_count = self.observable1.neighbors()
        self.assertEqual(len(vertices), 2)
        self.assertEqual(edge_count, 2)
