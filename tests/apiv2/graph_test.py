import datetime
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.entity import ThreatActor
from core.schemas.graph import Relationship
from core.schemas.indicator import Regex
from core.schemas.observable import Observable
from core.web import webapp

client = TestClient(webapp.app)

class SimpleGraphTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        self.observable1 = Observable(
            value="tomchop.me",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        self.observable2 = Observable(
            value="127.0.0.1",
            type="ip",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        self.entity1 = ThreatActor(name="actor0").save()

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

    def test_add_link_entity(self):
        response = client.post(
            "/api/v2/graph/add",
            json={
                "source": self.observable1.extended_id,
                "target": self.entity1.extended_id,
                "link_type": "uses",
                "description": "c2 infrastructure"
                }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNotNone(data['id'])
        self.assertEqual(data['source'], self.observable1.extended_id)
        self.assertEqual(data['target'], self.entity1.extended_id)
        self.assertEqual(data['type'], 'uses')
        self.assertEqual(data['description'], 'c2 infrastructure')

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


class ComplexGraphTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        self.observable1 = Observable(value="test1.com", type="hostname").save()
        self.observable2 = Observable(value="test2.com", type="hostname").save()
        self.observable3 = Observable(
            value="http://test1.com/admin", type="url").save()
        self.entity1 = ThreatActor(name="tester").save()
        self.indicator1 = Regex(name='test c2', pattern='test[0-9].com', location='network').save()
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
            }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['entities']), 1)
        relationship, entity = data['entities'][0]
        self.assertEqual(relationship['type'], 'infra')
        self.assertEqual(relationship['source'], self.entity1.extended_id)
        self.assertEqual(relationship['target'], self.observable1.extended_id)

        self.assertEqual(entity['type'], 'threat-actor')
        self.assertEqual(entity['name'], 'tester')

    def test_matches_exist(self):
        """Tests that indicator matches will surface."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test2.com"],
            }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Observable is not known, has not been added.
        self.assertEqual(data['unknown'], [])
        self.assertEqual(len(data['known']), 1)
        self.assertEqual(data['known'][0]['value'], 'test2.com')

        # Indicator matches, but no links have been added.
        self.assertEqual(len(data['matches']), 1)
        observable, indicator = data['matches'][0]
        self.assertEqual(observable, 'test2.com')
        self.assertEqual(indicator['name'], 'test c2')

    def test_matches_nonexist(self):
        """Tests that indicator matches will surface."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test3.com"],
            }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Observable is not known, has not been added.
        self.assertEqual(data['unknown'], ['test3.com'])

        # Indicator matches, but no links have been added.
        self.assertEqual(len(data['matches']), 1)
        observable, indicator = data['matches'][0]
        self.assertEqual(observable, 'test3.com')
        self.assertEqual(indicator['name'], 'test c2')

    def test_match_and_add(self):
        """Tests that indicator matches will surface."""
        response = client.post(
            "/api/v2/graph/match",
            json={
                "observables": ["test3.com"],
            }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Observable is not known, has not been added.
        self.assertEqual(data['unknown'], ['test3.com'])

        # Indicator matches, but no links have been added.
        self.assertEqual(len(data['matches']), 1)
        observable, indicator = data['matches'][0]
        self.assertEqual(observable, 'test3.com')
        self.assertEqual(indicator['name'], 'test c2')
