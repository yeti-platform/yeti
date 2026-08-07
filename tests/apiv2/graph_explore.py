import logging
import sys
import time
import unittest
from unittest import mock

from arango.exceptions import AQLQueryExecuteError
from fastapi.testclient import TestClient

from core import database_arango, graph_explore
from core.schemas import rbac, roles
from core.schemas.entity import ThreatActor
from core.schemas.observables.hostname import Hostname
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


def item_request(items: list[str], **overrides):
    request = {
        "schema_version": 1,
        "scope": {"kind": "items", "items": items},
        "direction": "any",
        "link_types": [],
        "target_types": [],
        "filters": [],
        "requested_limits": {"nodes": 2000, "edges": 10000},
    }
    request.update(overrides)
    return request


def query_request(query: dict, **scope_overrides):
    scope = {
        "kind": "query",
        "query": query,
        "sorting": [],
        "filter_aliases": [],
    }
    scope.update(scope_overrides)
    return {
        "schema_version": 1,
        "scope": scope,
        "direction": "any",
        "link_types": [],
        "target_types": [],
        "filters": [],
        "requested_limits": {"nodes": 2000, "edges": 10000},
    }


class GraphExploreTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.user = UserSensitive(
            username="graph-explore", password="test", enabled=True
        ).save()
        api_key = self.user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": api_key}
        ).json()
        client.headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    def tearDown(self) -> None:
        database_arango.RBAC_ENABLED = False
        rbac.RBAC_ENABLED = False
        database_arango.db.truncate()
        client.headers = {}
        logging.disable(logging.NOTSET)

    def test_item_scope_deduplicates_anchors_and_preserves_provenance(self):
        anchor_a = ThreatActor(name="anchor-a").save()
        anchor_b = ThreatActor(name="anchor-b").save()
        neighbor = Hostname(value="shared.example").save()
        edge_a = anchor_a.link_to(neighbor, "resolves", "first path")
        edge_b = anchor_b.link_to(neighbor, "uses", "second path")

        response = client.post(
            "/api/v2/graph/explore",
            json=item_request(
                [anchor_a.extended_id, anchor_a.extended_id, anchor_b.extended_id]
            ),
        )

        self.assertEqual(response.status_code, 200, response.json())
        data = response.json()
        self.assertEqual(
            data["scope"]["anchor_ids"],
            [anchor_a.extended_id, anchor_b.extended_id],
        )
        nodes = {node["id"]: node for node in data["nodes"]}
        self.assertEqual(nodes[anchor_a.extended_id]["role"], "anchor")
        self.assertEqual(nodes[neighbor.extended_id]["role"], "neighbor")
        self.assertEqual(
            nodes[neighbor.extended_id]["origin_ids"],
            [anchor_a.extended_id, anchor_b.extended_id],
        )
        self.assertEqual(
            {edge["id"] for edge in data["edges"]},
            {f"links/{edge_a.id}", f"links/{edge_b.id}"},
        )

    def test_item_scope_fails_atomically_when_any_anchor_is_missing(self):
        anchor = ThreatActor(name="available").save()

        response = client.post(
            "/api/v2/graph/explore",
            json=item_request([anchor.extended_id, "entities/missing"]),
        )

        self.assertEqual(response.status_code, 404, response.json())
        self.assertEqual(
            response.json()["detail"],
            "One or more requested objects are unavailable",
        )
        self.assertNotIn(anchor.extended_id, response.text)

    def test_item_scope_fails_atomically_for_an_inaccessible_anchor(self):
        available = ThreatActor(name="available").save()
        hidden = ThreatActor(name="hidden").save()
        self.user.link_to_acl(available, roles.Role.READER)
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True

        response = client.post(
            "/api/v2/graph/explore",
            json=item_request([available.extended_id, hidden.extended_id]),
        )

        self.assertEqual(response.status_code, 404, response.json())
        self.assertNotIn(hidden.extended_id, response.text)

    def test_item_scope_composes_relationship_and_target_filters(self):
        anchor = ThreatActor(name="anchor").save()
        hostname = Hostname(value="host.example").save()
        other = ThreatActor(name="other").save()
        anchor.link_to(hostname, "resolves", "wrong relationship")
        anchor.link_to(other, "uses", "wrong target")

        response = client.post(
            "/api/v2/graph/explore",
            json=item_request(
                [anchor.extended_id],
                link_types=["uses"],
                target_types=["hostname"],
            ),
        )

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(
            [node["id"] for node in response.json()["nodes"]], [anchor.extended_id]
        )
        self.assertEqual(response.json()["edges"], [])

    def test_item_scope_preserves_directed_parallel_relationships(self):
        anchor = ThreatActor(name="anchor").save()
        neighbor = Hostname(value="parallel.example").save()
        first = anchor.link_to(neighbor, "resolves", "first observation")
        second = anchor.link_to(neighbor, "uses", "second observation")

        response = client.post(
            "/api/v2/graph/explore", json=item_request([anchor.extended_id])
        )

        self.assertEqual(response.status_code, 200, response.json())
        edges = {edge["id"]: edge for edge in response.json()["edges"]}
        self.assertEqual(set(edges), {f"links/{first.id}", f"links/{second.id}"})
        self.assertEqual(
            {(edge["source"], edge["target"]) for edge in edges.values()},
            {(anchor.extended_id, neighbor.extended_id)},
        )

    def test_item_scope_does_not_return_an_inaccessible_neighbor_or_edge(self):
        anchor = ThreatActor(name="available").save()
        hidden = Hostname(value="hidden.example").save()
        anchor.link_to(hidden, "resolves", "hidden relationship")
        self.user.link_to_acl(anchor, roles.Role.READER)
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True

        response = client.post(
            "/api/v2/graph/explore", json=item_request([anchor.extended_id])
        )

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(
            [node["id"] for node in response.json()["nodes"]], [anchor.extended_id]
        )
        self.assertEqual(response.json()["edges"], [])
        self.assertNotIn(hidden.extended_id, response.text)

    def test_query_scope_is_stable_and_returns_induced_edges(self):
        actor_b = ThreatActor(name="bravo").save()
        actor_a = ThreatActor(name="alpha").save()
        relationship = actor_b.link_to(actor_a, "targets", "ordered evidence")
        Hostname(value="outside.example").save()

        response = client.post(
            "/api/v2/graph/explore",
            json=query_request({"root_type": "entity"}, sorting=[["name", True]]),
        )

        self.assertEqual(response.status_code, 200, response.json())
        data = response.json()
        self.assertEqual(data["scope"]["accessible_match_count"], 2)
        self.assertEqual([node["label"] for node in data["nodes"]], ["alpha", "bravo"])
        self.assertTrue(all(node["role"] == "scope_match" for node in data["nodes"]))
        self.assertEqual(data["edges"][0]["id"], f"links/{relationship.id}")
        self.assertEqual(data["scope"]["ranking"], [["name", True], ["_id", True]])

    def test_query_scope_can_return_an_empty_graph(self):
        response = client.post(
            "/api/v2/graph/explore",
            json=query_request({"name": "does-not-exist"}),
        )

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(response.json()["nodes"], [])
        self.assertEqual(response.json()["edges"], [])
        self.assertEqual(response.json()["scope"]["accessible_match_count"], 0)

    def test_query_scope_supports_a_time_range(self):
        old = ThreatActor(name="old").save()
        new = ThreatActor(name="new").save()
        entities = database_arango.db.collection("entities")
        entities.update({"_key": old.id, "modified": "2020-06-01T00:00:00Z"})
        entities.update({"_key": new.id, "modified": "2024-06-01T00:00:00Z"})

        response = client.post(
            "/api/v2/graph/explore",
            json=query_request(
                {
                    "root_type": "entity",
                    "modified__gte": "2020-01-01",
                    "modified__lte": "2020-12-31",
                }
            ),
        )

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(
            [node["id"] for node in response.json()["nodes"]], [old.extended_id]
        )

    def test_query_scope_supports_tags_and_concrete_types(self):
        tagged = Hostname(value="tagged.example").save()
        tagged.tag(["graph-scope"])
        Hostname(value="untagged.example").save()
        time.sleep(0.5)

        response = client.post(
            "/api/v2/graph/explore",
            json=query_request({"tags": ["graph-scope"], "type": "hostname"}),
        )

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(
            [node["id"] for node in response.json()["nodes"]], [tagged.extended_id]
        )

    def test_query_scope_totals_and_edges_are_rbac_filtered(self):
        visible = ThreatActor(name="visible").save()
        hidden = ThreatActor(name="hidden").save()
        visible.link_to(hidden, "related", "must not leak")
        self.user.link_to_acl(visible, roles.Role.READER)
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True

        response = client.post(
            "/api/v2/graph/explore", json=query_request({"root_type": "entity"})
        )

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(response.json()["scope"]["accessible_match_count"], 1)
        self.assertEqual(
            [node["id"] for node in response.json()["nodes"]], [visible.extended_id]
        )
        self.assertEqual(response.json()["edges"], [])
        self.assertNotIn(hidden.extended_id, response.text)

    def test_item_scope_reports_node_budget_truncation(self):
        anchor = ThreatActor(name="anchor").save()
        anchor.link_to(Hostname(value="one.example").save(), "resolves", "one")
        anchor.link_to(Hostname(value="two.example").save(), "resolves", "two")
        request = item_request([anchor.extended_id])
        request["requested_limits"] = {"nodes": 2, "edges": 10000}

        response = client.post("/api/v2/graph/explore", json=request)

        self.assertEqual(response.status_code, 200, response.json())
        budget = response.json()["budget"]
        self.assertEqual(budget["returned_nodes"], 2)
        self.assertTrue(budget["is_truncated"])
        self.assertIn("node_limit", budget["reasons"])

    def test_zero_edge_budget_does_not_return_orphan_neighbors(self):
        anchor = ThreatActor(name="anchor").save()
        anchor.link_to(Hostname(value="neighbor.example").save(), "resolves", "one")
        request = item_request([anchor.extended_id])
        request["requested_limits"] = {"nodes": 2, "edges": 0}

        response = client.post("/api/v2/graph/explore", json=request)

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(
            [node["id"] for node in response.json()["nodes"]], [anchor.extended_id]
        )
        self.assertEqual(response.json()["edges"], [])
        self.assertEqual(response.json()["budget"]["reasons"], ["edge_limit"])

    def test_item_scope_deduplicates_rows_before_applying_edge_budget(self):
        anchors = [ThreatActor(name=f"anchor-{index}").save() for index in range(4)]
        neighbor = Hostname(value="last.example").save()
        first = anchors[0].link_to(anchors[1], "related", "first")
        second = anchors[2].link_to(anchors[3], "related", "second")
        third = anchors[3].link_to(neighbor, "resolves", "third")
        request = item_request([anchor.extended_id for anchor in anchors])
        request["requested_limits"] = {"nodes": 5, "edges": 3}

        response = client.post("/api/v2/graph/explore", json=request)

        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(
            {edge["id"] for edge in response.json()["edges"]},
            {f"links/{first.id}", f"links/{second.id}", f"links/{third.id}"},
        )
        self.assertFalse(response.json()["budget"]["is_truncated"])

    def test_limits_and_scope_shape_are_strict(self):
        anchor = ThreatActor(name="anchor").save()
        second_anchor = ThreatActor(name="second-anchor").save()
        over_limit = item_request([anchor.extended_id])
        over_limit["requested_limits"]["nodes"] = 5001
        undersized_limit = item_request([anchor.extended_id, second_anchor.extended_id])
        undersized_limit["requested_limits"]["nodes"] = 1
        extra_field = item_request([anchor.extended_id])
        extra_field["scope"]["source"] = anchor.extended_id

        self.assertEqual(
            client.post("/api/v2/graph/explore", json=over_limit).status_code, 422
        )
        self.assertEqual(
            client.post("/api/v2/graph/explore", json=extra_field).status_code, 422
        )
        self.assertEqual(
            client.post("/api/v2/graph/explore", json=undersized_limit).status_code,
            422,
        )

    def test_timeout_during_cursor_iteration_is_normalized(self):
        timeout = AQLQueryExecuteError.__new__(AQLQueryExecuteError)
        Exception.__init__(timeout, "query killed")
        timeout.error_code = 1500

        class TimedOutCursor:
            def __iter__(self):
                raise timeout

        fake_database = mock.Mock()
        fake_database.aql.execute.return_value = TimedOutCursor()
        with mock.patch.object(database_arango, "db", fake_database):
            with self.assertRaises(TimeoutError):
                graph_explore._execute_aql("RETURN 1", {})

    def test_timeout_returns_generic_retryable_error(self):
        anchor = ThreatActor(name="anchor").save()

        with mock.patch(
            "core.web.apiv2.graph.explore_graph",
            side_effect=TimeoutError,
        ):
            response = client.post(
                "/api/v2/graph/explore", json=item_request([anchor.extended_id])
            )

        self.assertEqual(response.status_code, 503, response.json())
        self.assertEqual(
            response.json()["detail"], "Graph exploration timed out; retry later"
        )
        self.assertNotIn(anchor.extended_id, response.text)

    def test_request_audit_suppresses_explore_body(self):
        anchor = ThreatActor(name="sensitive-anchor").save()

        with mock.patch.object(webapp.logger, "info") as audit_info:
            response = client.post(
                "/api/v2/graph/explore", json=item_request([anchor.extended_id])
            )

        self.assertEqual(response.status_code, 200, response.json())
        explore_calls = [
            call
            for call in audit_info.call_args_list
            if call.kwargs.get("extra", {}).get("path") == "/api/v2/graph/explore"
        ]
        self.assertEqual(len(explore_calls), 1)
        self.assertEqual(explore_calls[0].kwargs["extra"]["body"], b"")

    def test_operation_log_contains_only_sanitized_graph_metadata(self):
        anchor = ThreatActor(name="sensitive-anchor").save()

        with mock.patch("core.web.apiv2.graph.logger.info") as operation_info:
            response = client.post(
                "/api/v2/graph/explore", json=item_request([anchor.extended_id])
            )

        self.assertEqual(response.status_code, 200, response.json())
        metadata = operation_info.call_args.kwargs["extra"]
        self.assertEqual(
            set(metadata),
            {
                "scope_kind",
                "outcome",
                "duration_ms",
                "returned_nodes",
                "returned_edges",
                "is_truncated",
            },
        )
        self.assertNotIn(anchor.extended_id, str(metadata))


if __name__ == "__main__":
    unittest.main()
