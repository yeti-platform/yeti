import datetime

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.observables import hostname, ipv4
from core.schemas.graph import Relationship

import unittest
from core.schemas.observables.file import File
from core.schemas.observables.url import Url

from core.web import webapp


class ObservableTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_observable_create(self) -> None:
        result = hostname.Hostname(value="toto.com").save()
        self.assertIsNotNone(result.id)
        self.assertEqual(result.value, "toto.com")

    def test_observable_find(self) -> None:
        result = hostname.Hostname(value="toto.com").save()
        observable = Observable.find(value="toto.com")
        self.assertIsNotNone(observable)
        assert observable is not None
        self.assertEqual(observable.value, "toto.com")  #

        observable = Observable.find(value="tata.com")
        self.assertIsNone(observable)

    def test_observable_get(self) -> None:
        result = hostname.Hostname(value="toto.com").save()
        assert result.id is not None
        observable = Observable.get(result.id)
        assert observable is not None
        self.assertIsNotNone(observable)
        self.assertEqual(observable.value, "toto.com")

    def test_file(self):
        file = File(value="test.txt")
        file.save()

    def test_file_update(self):
        file = File(value="test.txt")
        file.md5 = "1234567890"
        file.save()

    def test_url(self):
        url = Url(value="https://www.google.com")
        url.save()

    def test_observable_filter(self):
        obs1 = hostname.Hostname(value="test1.com").save()
        obs2 = hostname.Hostname(value="test2.com").save()

        result, total = Observable.filter(args={"value": "test"})
        self.assertEqual(len(result), 2)
        self.assertEqual(total, 2)
        self.assertEqual(result[0].id, obs1.id)
        self.assertEqual(result[0].value, "test1.com")
        self.assertEqual(result[1].id, obs2.id)
        self.assertEqual(result[1].value, "test2.com")

    def test_observable_filter_in(self):
        obs1 = hostname.Hostname(value="test1.com").save()
        obs2 = hostname.Hostname(value="test2.com").save()
        obs3 = hostname.Hostname(value="test3.com").save()

        result, total = Observable.filter(
            args={"value__in": ["test1.com", "test3.com"]}
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(total, 2)
        self.assertEqual(result[0].id, obs1.id)
        self.assertEqual(result[0].value, "test1.com")
        self.assertEqual(result[1].id, obs3.id)
        self.assertEqual(result[1].value, "test3.com")

    def test_observable_link_to(self) -> None:
        observable1 = hostname.Hostname(value="toto.com").save()
        observable2 = hostname.Hostname(value="tata.com").save()

        relationship = observable1.link_to(observable2, "test_reltype", "desc1")
        self.assertEqual(relationship.type, "test_reltype")
        self.assertEqual(relationship.description, "desc1")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)

    def test_observable_update_link(self) -> None:
        observable1 = hostname.Hostname(value="toto.com").save()
        observable2 = hostname.Hostname(value="tata.com").save()

        relationship = observable1.link_to(observable2, "test_reltype", "desc1")
        relationship = observable1.link_to(observable2, "test_reltype", "desc2")
        self.assertEqual(relationship.type, "test_reltype")
        self.assertEqual(relationship.description, "desc2")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)
        self.assertEqual(all_relationships[0].description, "desc2")

    def test_observable_neighbor(self) -> None:
        observable1 = hostname.Hostname(value="tomchop.me").save()
        observable2 = ipv4.IPv4(value="127.0.0.1").save()

        relationship = observable1.link_to(observable2, "resolves", "DNS resolution")
        self.assertEqual(relationship.type, "resolves")

        vertices, edges, count = observable1.neighbors()

        self.assertEqual(len(edges), 1)
        self.assertEqual(count, 1)
        self.assertEqual(len(vertices), 1)

        relationships = edges
        self.assertEqual(relationships[0].source, observable1.extended_id)
        self.assertEqual(relationships[0].target, observable2.extended_id)
        self.assertEqual(relationships[0].description, "DNS resolution")
        self.assertEqual(relationships[0].type, "resolves")

        self.assertIn(observable2.extended_id, vertices)
        neighbor = vertices[observable2.extended_id]
        self.assertEqual(neighbor.id, observable2.id)

    def test_add_context(self) -> None:
        """Tests that one or more contexts is added and persisted in the DB."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source2", {"abc": 123, "def": 456})

        assert observable.id is not None
        observable = Observable.get(observable.id)
        self.assertEqual(len(observable.context), 2)
        self.assertEqual(observable.context[0]["abc"], 123)
        self.assertEqual(observable.context[0]["source"], "test_source")
        self.assertEqual(observable.context[1]["abc"], 123)
        self.assertEqual(observable.context[1]["source"], "test_source2")

    def test_add_dupe_context(self) -> None:
        """Tests that identical contexts aren't added twice."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 123, "def": 456})
        self.assertEqual(len(observable.context), 1)

    def test_add_new_context_with_same_source(self) -> None:
        """Tests that diff contexts with same source are added separately."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 123, "def": 666})
        self.assertEqual(len(observable.context), 2)

    def test_add_new_context_with_same_source_and_ignore_field(self) -> None:
        """Tests that the context is updated if the difference is not being
        compared."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context(
            "test_source", {"abc": 123, "def": 666}, skip_compare={"def"}
        )
        self.assertEqual(len(observable.context), 1)
        self.assertEqual(observable.context[0]["def"], 666)

    def test_delete_context(self) -> None:
        """Tests that a context is deleted if contents fully match."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable = observable.add_context("test_source", {"abc": 123, "def": 456})
        observable = observable.delete_context("test_source", {"def": 456, "abc": 123})
        assert observable.id is not None
        observable = Observable.get(observable.id)  # type: ignore

        self.assertEqual(len(observable.context), 0)

    def test_delete_context_diff(self) -> None:
        """Tests that a context is not deleted if contents don't match."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable = observable.add_context("test_source", {"abc": 123, "def": 456})
        observable = observable.delete_context("test_source", {"def": 456, "abc": 000})
        observable = Observable.get(observable.id)  # type: ignore
        self.assertEqual(len(observable.context), 1)

    def tests_delete_context_skip_compare(self) -> None:
        """Tests that a context is deleted if the difference is not being
        compared."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable = observable.add_context("test_source", {"abc": 123, "def": 456})
        observable = observable.delete_context(
            "test_source", {"abc": 000, "def": 456}, skip_compare={"abc"}
        )
        observable = Observable.get(observable.id)  # type: ignore
        self.assertEqual(len(observable.context), 0)

    def test_duplicate_value(self) -> None:
        """Tests saving two observables with the same value return the same observable."""
        obs1 = hostname.Hostname(value="tomchop.me").save()
        obs2 = hostname.Hostname(value="tomchop.me").save()
        self.assertEqual(obs1.id, obs2.id)
