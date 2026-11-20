import concurrent.futures
import time
import unittest
from unittest import mock

from arango.aql import AQL
from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.entity import Campaign, Entity, Malware
from core.schemas.graph import GraphFilter, Relationship
from core.schemas.indicator import DiamondModel, Indicator, Regex
from core.schemas.observables import hostname, ipv4, user_agent
from core.web import webapp

client = TestClient(webapp.app)


class GraphTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.observable1 = hostname.Hostname(value="tomchop.me").save()
        self.observable2 = ipv4.IPv4(value="127.0.0.1").save()
        self.observable3 = ipv4.IPv4(value="8.8.8.8").save()
        self.observable4 = user_agent.UserAgent(value="Mozilla/5.0").save()
        self.entity1 = Malware(name="plugx").save()
        self.entity2 = Campaign(name="campaign1").save()
        self.entity3 = Campaign(name="campaign2").save()

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

    def test_concurrent_link_to_same_pair_is_atomic(self) -> None:
        """Concurrent link_to() calls for the same (source, target, type) must
        collapse into one edge with an accurate count, not one edge per
        caller with the count updates racing each other."""
        concurrent_calls = 20
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            list(
                executor.map(
                    lambda _: self.observable1.link_to(
                        self.observable2, "resolves", "DNS resolution"
                    ),
                    range(concurrent_calls),
                )
            )

        matching = [
            r
            for r in Relationship.list()
            if r.source == self.observable1.extended_id
            and r.target == self.observable2.extended_id
            and r.type == "resolves"
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].count, concurrent_calls)

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

        query = {"type": "campaign"}

        sorting = [["total_links", True]]
        time.sleep(1)
        entities, total = Entity.filter(
            query_args=query, offset=0, count=20, sorting=sorting, links_count=True
        )
        assert total == 2
        assert entities[0].name == "campaign2"
        assert entities[1].name == "campaign1"

        sorting = [["total_links", False]]
        entities, total = Entity.filter(
            query_args=query, offset=0, count=20, sorting=sorting, links_count=True
        )
        assert total == 2
        assert entities[0].name == "campaign1"
        assert entities[1].name == "campaign2"

    def _total_links(self, cls) -> dict[str, int]:
        """Returns the total_links filter() computes for each object, by name.

        The value is read from the query's documents on their way into
        load(), because the entity and indicator models do not declare it.
        """
        load = cls.load
        total_links = {}

        def record(document):
            total_links[document["name"]] = document["total_links"]
            return load(document)

        with mock.patch.object(cls, "load", side_effect=record):
            cls.filter(query_args={}, links_count=True)
        return total_links

    def test_filter_links_count_total_links(self):
        """total_links is the number of links an object has, whichever way
        they point."""
        Campaign(name="campaign3").save()
        regex1 = Regex(
            name="regex1", pattern="asd", diamond=DiamondModel.capability
        ).save()
        Regex(name="regex2", pattern="asd", diamond=DiamondModel.capability).save()

        self.entity2.link_to(self.observable2, "a", "description_aaaa")
        self.entity2.link_to(self.observable2, "b", "same observable, other type")
        self.entity2.link_to(self.observable3, "c", "description_ccc")
        self.entity2.link_to(self.observable4, "d", "description_ddd")
        self.entity2.link_to(self.entity1, "uses", "description_uses")

        self.entity3.link_to(self.observable2, "a", "description_aaaa")
        self.observable3.link_to(self.entity3, "b", "description_bbb")

        regex1.link_to(self.entity1, "indicates", "description_indicates")
        self.observable1.link_to(regex1, "matches", "description_matches")

        self.assertEqual(
            self._total_links(Entity),
            {"plugx": 2, "campaign1": 5, "campaign2": 2, "campaign3": 0},
        )
        self.assertEqual(self._total_links(Indicator), {"regex1": 2, "regex2": 0})

    def test_filter_links_count_counts_a_link_to_a_missing_object(self):
        """A link still counts when the object at its other end is gone."""
        self.entity2.link_to(self.observable2, "a", "description_aaaa")
        self.entity2.link_to(self.observable3, "c", "description_ccc")
        # Not Observable.delete(), which removes the object's links with it.
        database_arango.db.db.collection("observables").delete(self.observable3.id)

        self.assertEqual(self._total_links(Entity)["campaign1"], 2)

    def test_filter_links_count_does_not_read_the_linked_objects(self):
        """Counting the links of the rows on a page must not read the objects
        at their other end: one object with thousands of links would slow
        down every page it is on."""
        self.entity2.link_to(self.observable2, "a", "description_aaaa")
        # StandardDatabase.aql builds a new AQL object on every access, so
        # the spy has to go on the class.
        with mock.patch.object(
            AQL, "execute", autospec=True, side_effect=AQL.execute
        ) as execute:
            Entity.filter(query_args={}, count=50, links_count=True)
        page_queries = [
            call
            for call in execute.call_args_list
            if "FOR o IN @@collection" in call.args[1]
        ]
        self.assertEqual(len(page_queries), 1, execute.call_args_list)
        plan = database_arango.db.db.aql.explain(
            page_queries[0].args[1], bind_vars=page_queries[0].kwargs["bind_vars"]
        )
        reading_linked_objects = [
            node
            for node in plan["nodes"]
            if node["type"] == "TraversalNode" and node["options"]["produceVertices"]
        ]
        self.assertEqual(reading_linked_objects, [])
