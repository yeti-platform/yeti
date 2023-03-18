import datetime

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.graph import Relationship

import unittest

from core.web import webapp

class ObservableTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_observable_create(self) -> None:
        result = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        self.assertIsNotNone(result.id)
        self.assertEqual(result.value, "toto.com")

    def test_observable_find(self) -> None:
        result = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        observable = Observable.find(value="toto.com")
        self.assertIsNotNone(observable)
        self.assertEqual(observable.value, "toto.com")  # type: ignore

        observable = Observable.find(value="tata.com")
        self.assertIsNone(observable)

    def test_observable_get(self) -> None:
        result = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        observable = Observable.get(result.id)  # type: ignore
        self.assertIsNotNone(observable)
        self.assertEqual(observable.value, "toto.com")  # type: ignore

    def test_observable_link_to(self) -> None:
        observable1 = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        observable2 = Observable(
            value="tata.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()

        relationship = observable1.link_to(observable2, "test_reltype", "desc1")
        self.assertEqual(relationship.type, "test_reltype")
        self.assertEqual(relationship.description, "desc1")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)

    def test_observable_update_link(self) -> None:
        observable1 = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        observable2 = Observable(
            value="tata.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()

        relationship = observable1.link_to(observable2, "test_reltype", "desc1")
        relationship = observable1.link_to(observable2, "test_reltype", "desc2")
        self.assertEqual(relationship.type, "test_reltype")
        self.assertEqual(relationship.description, "desc2")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)
        self.assertEqual(all_relationships[0].description, "desc2")

    def test_observable_neighbor(self) -> None:
        observable1 = Observable(
            value="tomchop.me",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        observable2 = Observable(
            value="127.0.0.1",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()

        relationship = observable1.link_to(
            observable2, "resolves", "DNS resolution")
        self.assertEqual(relationship.type, "resolves")

        observable1_neighbors = observable1.neighbors()

        self.assertEqual(len(observable1_neighbors.edges), 1)
        self.assertEqual(len(observable1_neighbors.vertices), 1)

        relationships = observable1_neighbors.edges
        self.assertEqual(relationships[0].source, observable1.extended_id)
        self.assertEqual(relationships[0].target, observable2.extended_id)
        self.assertEqual(relationships[0].description, "DNS resolution")
        self.assertEqual(relationships[0].type, "resolves")

        self.assertIn(observable2.extended_id, observable1_neighbors.vertices)
        neighbor = observable1_neighbors.vertices[observable2.extended_id]
        self.assertEqual(neighbor.id, observable2.id)
