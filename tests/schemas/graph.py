import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.entity import Campaign, Entity, Malware
from core.schemas.graph import GraphFilter, Relationship
from core.schemas.observables import hostname, ipv4, user_agent
from core.web import webapp

client = TestClient(webapp.app)


class GraphTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.observable1 = hostname.Hostname(value="tomchop.me").save()
        self.observable2 = ipv4.IPv4(value="127.0.0.1").save()
        self.observable3 = ipv4.IPv4(value="8.8.8.8").save()
        self.observable4 = user_agent.UserAgent(value="Mozilla/5.0").save()
        self.entity1 = Malware(name="plugx").save()
        self.entity2 = Campaign(name="campaign1").save()
        self.entity3 = Campaign(name="campaign2").save()

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

    def test_observable_to_observable_link_count(self) -> None:
        """Tests the update of link count between two observables."""
        for i in range(10):
            self.relationship = self.observable2.link_to(
                self.observable4, "uses", "User agent"
            )
        self.assertEqual(self.relationship.count, 10)

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

    def test_entity_to_observable_link_count(self) -> None:
        """Tests the update of link count between an observable and an entity."""
        for i in range(10):
            self.relationship = self.entity2.link_to(
                self.observable2, "observes", "Observes network traffic"
            )
        self.assertEqual(self.relationship.count, 10)

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

    def test_neighbors_filter(self):
        """Tests that a link between two nodes is bidirectional."""
        self.observable1.link_to(self.observable2, "a", "description_aaaa")
        self.observable1.link_to(self.observable3, "c", "description_ccc")

        # filter on edge description
        vertices, edges, edge_count = self.observable1.neighbors(
            filter=[GraphFilter(key="description", value="_ccc", operator="=~")]
        )
        self.assertEqual(len(vertices), 1)
        self.assertEqual(edge_count, 1)
        self.assertEqual(
            vertices[self.observable3.extended_id].value, self.observable3.value
        )

        # filter on vertice value
        vertices, edges, edge_count = self.observable1.neighbors(
            filter=[GraphFilter(key="value", value="8.8", operator="=~")]
        )
        self.assertEqual(len(vertices), 1)
        self.assertEqual(edge_count, 1)
        self.assertEqual(
            vertices[self.observable3.extended_id].value, self.observable3.value
        )

        vertices, edges, edge_count = self.observable1.neighbors()
        self.assertEqual(len(vertices), 2)
        self.assertEqual(edge_count, 2)

    def test_neighbors_filter_two_hops(self):
        """Tests that a link between two nodes is bidirectional."""
        self.observable1.link_to(self.observable2, "a", "description_aaaa_to_b")
        self.observable2.link_to(self.observable3, "b", "description_bbbb_to_c")
        observable4 = ipv4.IPv4(value="1.1.1.1").save()
        self.observable2.link_to(observable4, "c", "description_bbbb_to_d")

        vertices, edges, edge_count = self.observable1.neighbors(min_hops=1, max_hops=2)
        self.assertEqual(len(vertices), 3)
        self.assertEqual(len(edges), 3)
        self.assertEqual(len(edges[0]), 1)  # First hop counts as a path
        self.assertEqual(len(edges[1]), 2)  # First two-hop path
        self.assertEqual(len(edges[2]), 2)  # Second two-hop path

        vertices, edges, edge_count = self.observable1.neighbors(
            min_hops=1,
            max_hops=2,
            filter=[GraphFilter(key="description", value="bbbb_to_d", operator="=~")],
        )
        self.assertEqual(len(vertices), 2)
        self.assertEqual(len(edges), 1)
        self.assertEqual(len(edges[0]), 2)
        self.assertEqual(edges[0][0].source, self.observable1.extended_id)
        self.assertEqual(edges[0][0].target, self.observable2.extended_id)
        self.assertEqual(edges[0][1].source, self.observable2.extended_id)
        self.assertEqual(edges[0][1].target, observable4.extended_id)
        self.assertEqual(edges[0][0].description, "description_aaaa_to_b")
        self.assertEqual(edges[0][1].description, "description_bbbb_to_d")

        vertices, edges, edge_count = self.observable1.neighbors(
            min_hops=1,
            max_hops=3,
            filter=[GraphFilter(key="value", value="1.1.1.1", operator="=~")],
        )
        self.assertEqual(len(vertices), 2)
        self.assertEqual(len(edges), 1)  # Only one path, two-hops
        self.assertEqual(len(edges[0]), 2)
        self.assertEqual(edges[0][0].source, self.observable1.extended_id)
        self.assertEqual(edges[0][0].target, self.observable2.extended_id)
        self.assertEqual(edges[0][1].source, self.observable2.extended_id)
        self.assertEqual(edges[0][1].target, observable4.extended_id)
        self.assertEqual(edges[0][0].description, "description_aaaa_to_b")
        self.assertEqual(edges[0][1].description, "description_bbbb_to_d")

    def test_filter_sorted_by_related_obserables_count(self):
        """Tests entities sorted by number of related observables."""
        self.entity2.link_to(self.observable2, "a", "description_aaaa")
        self.entity2.link_to(self.observable3, "c", "description_ccc")
        self.entity2.link_to(self.observable4, "d", "description_ddd")

        self.entity3.link_to(self.observable2, "a", "description_aaaa")
        self.entity3.link_to(self.observable3, "c", "description_ccc")

        assert self.entity2.related_observables_count == 3
        assert self.entity3.related_observables_count == 2

        query = {"type": "campaign"}

        sorting = [["related_observables_count", True]]
        entities, total = Entity.filter(
            query_args=query, offset=0, count=20, sorting=sorting
        )
        assert total == 2
        assert entities[0].name == "campaign2"
        assert entities[1].name == "campaign1"

        sorting = [["related_observables_count", False]]
        entities, total = Entity.filter(
            query_args=query, offset=0, count=20, sorting=sorting
        )
        assert total == 2
        assert entities[0].name == "campaign1"
        assert entities[1].name == "campaign2"
