import logging
import sys
import unittest

from core import database_arango
from core.schemas.entity import ThreatActor
from core.schemas.graph import Relationship
from core.schemas.indicator import Regex
from core.schemas.observables import hostname, ipv4, url
from core.schemas.user import UserSensitive
from core.web import webapp
from fastapi.testclient import TestClient

client = TestClient(webapp.app)


class SimpleGraphTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}
        self.observable1 = hostname.Hostname(value="tomchop.me").save()
        self.observable2 = ipv4.IPv4(value="127.0.0.1").save()
        self.entity1 = ThreatActor(name="actor0").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_get_neighbors(self):
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution"
        )
        response = client.post(
            "/api/v2/graph/search",
            json={
                "source": self.observable1.extended_id,
                "hops": 1,
                "graph": "links",
                "direction": "any",
                "include_original": False,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data["vertices"]), 1)
        neighbor = data["vertices"][self.observable2.extended_id]
        self.assertEqual(neighbor["value"], "127.0.0.1")
        self.assertEqual(neighbor["id"], self.observable2.id)

        edges = data["paths"]
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0][0]["source"], self.observable1.extended_id)
        self.assertEqual(edges[0][0]["target"], self.observable2.extended_id)
        self.assertEqual(edges[0][0]["type"], "resolves")

    def test_get_neighbors_tag(self):
        self.entity1.tag(['hacker1'])
        self.observable1.tag(['hacker1'])

        response = client.post(
            "/api/v2/graph/search",
            json={
                "source": self.observable1.extended_id,
                "hops": 2,
                "graph": "tagged",
                "direction": "any",
                "include_original": False,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data["vertices"]), 2)
        self.assertEqual(data["total"], 1)

        self.assertIn(self.entity1.extended_id, data["vertices"])

    def test_neighbors_go_both_ways(self):
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution"
        )

        response = client.post(
            "/api/v2/graph/search",
            json={
                "source": self.observable2.extended_id,
                "hops": 1,
                "graph": "links",
                "direction": "any",
                "include_original": False,
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["vertices"]), 1)
        neighbor = data["vertices"][self.observable1.extended_id]
        self.assertEqual(neighbor["value"], "tomchop.me")
        self.assertEqual(neighbor["id"], self.observable1.id)

        response = client.post(
            "/api/v2/graph/search",
            json={
                "source": self.observable1.extended_id,
                "hops": 1,
                "graph": "links",
                "direction": "any",
                "include_original": False,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data["vertices"]), 1)
        neighbor = data["vertices"][self.observable2.extended_id]
        self.assertEqual(neighbor["value"], "127.0.0.1")
        self.assertEqual(neighbor["id"], self.observable2.id)

    def test_add_link(self):
        response = client.post(
            "/api/v2/graph/add",
            json={
                "source": self.observable1.extended_id,
                "target": self.observable2.extended_id,
                "link_type": "resolves",
                "description": "DNS resolution",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNotNone(data["id"])
        self.assertEqual(data["source"], self.observable1.extended_id)
        self.assertEqual(data["target"], self.observable2.extended_id)
        self.assertEqual(data["type"], "resolves")
        self.assertEqual(data["description"], "DNS resolution")

    def test_add_link_entity(self):
        response = client.post(
            "/api/v2/graph/add",
            json={
                "source": self.observable1.extended_id,
                "target": self.entity1.extended_id,
                "link_type": "uses",
                "description": "c2 infrastructure",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNotNone(data["id"])
        self.assertEqual(data["source"], self.observable1.extended_id)
        self.assertEqual(data["target"], self.entity1.extended_id)
        self.assertEqual(data["type"], "uses")
        self.assertEqual(data["description"], "c2 infrastructure")

    def test_delete_link(self):
        """Tests that a relationship can be deleted."""
        self.relationship = self.observable1.link_to(
            self.observable2, "resolves", "DNS resolution"
        )
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)

        response = client.delete(f"/api/v2/graph/{self.relationship.id}")
        self.assertEqual(response.status_code, 200)
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 0)


class ComplexGraphTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}
        self.observable1 = hostname.Hostname(value="test1.com").save()
        self.observable1.tag(['tag1', 'tag2'])
        self.observable2 = hostname.Hostname(value="test2.com").save()
        self.observable3 = url.Url(value="http://test1.com/admin").save()
        self.entity1 = ThreatActor(name="tester").save()
        self.indicator1 = Regex(
            name="test c2",
            pattern="test[0-9].com",
            location="network",
            diamond="capability",
        ).save()
        self.observable1.link_to(self.observable3, "url", "URL on hostname.")
        self.entity1.link_to(self.observable1, "infra", "Known infrastructure.")

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_existing_links(self):
        """Checks that existing links surface in analysis."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test1.com"],
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["entities"]), 1)
        relationship, entity = data["entities"][0]
        self.assertEqual(relationship["type"], "infra")
        self.assertEqual(relationship["source"], self.entity1.extended_id)
        self.assertEqual(relationship["target"], self.observable1.extended_id)

        self.assertEqual(entity["type"], "threat-actor")
        self.assertEqual(entity["name"], "tester")

    def test_matches_exist(self):
        """Tests that indicator matches will surface."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test2.com"],
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Observable is not known, has not been added.
        self.assertEqual(data["unknown"], [])
        self.assertEqual(len(data["known"]), 1)
        self.assertEqual(data["known"][0]["value"], "test2.com")

        # Indicator matches, but no links have been added.
        self.assertEqual(len(data["matches"]), 1)
        observable, indicator = data["matches"][0]
        self.assertEqual(observable, "test2.com")
        self.assertEqual(indicator["name"], "test c2")

    def test_matches_nonexist(self):
        """Tests that uknown observables surface and match."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test3.com"],
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Observable is not known, has not been added.
        self.assertEqual(data["unknown"], ["test3.com"])

        # Indicator matches, but no links have been added.
        self.assertEqual(len(data["matches"]), 1)
        observable, indicator = data["matches"][0]
        self.assertEqual(observable, "test3.com")
        self.assertEqual(indicator["name"], "test c2")

    def test_match_and_add(self):
        """Tests that unknown observables are added."""
        response = client.post(
            "/api/v2/graph/match",
            json={"observables": ["test3.com"], "add_unknown": True},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Observable is known, has been added.
        self.assertEqual(len(data["known"]), 1)
        self.assertEqual(data["known"][0]["value"], "test3.com")

        # Indicator matches, but no links have been added.
        self.assertEqual(len(data["matches"]), 1)
        observable, indicator = data["matches"][0]
        self.assertEqual(observable, "test3.com")
        self.assertEqual(indicator["name"], "test c2")

    def test_match_add_with_type(self):
        """Tests that unknown observables are added."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test3.com"],
                "add_unknown": True,
                "add_type": "generic",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Observable is known, has been added.
        self.assertEqual(len(data["known"]), 1)
        self.assertEqual(data["known"][0]["value"], "test3.com")
        self.assertEqual(data["known"][0]["type"], "generic")

    def test_match_add_with_wrong_type_fails(self):
        """Tests that unknown observables are added."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test3.com"],
                "add_unknown": True,
                "add_type": "WRONG_TYPE",
            },
        )
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertIn("add_type", data["detail"][0]["loc"])

    def test_match_known_observables_have_tags(self):
        """Tests that observables have all tags."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test1.com"],
                "add_unknown": False
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        # Observable is known, has been added.
        self.assertEqual(len(data["known"]), 1)
        self.assertEqual(data["known"][0]["value"], "test1.com")
        self.assertEqual(sorted(data["known"][0]["tags"].keys()), ["tag1", "tag2"])
