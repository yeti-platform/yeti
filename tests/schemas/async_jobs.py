import unittest

from core import database_arango
from core.schemas.entity import Malware
from core.schemas.observables import ipv4
from core.schemas.tag import Tag


class AsyncJobResultsTest(unittest.TestCase):
    """Every async job Yeti submits must have its result fetched.

    Collections are opened through ``begin_async_execution(return_result=True)``,
    so ArangoDB stores each job's result in memory until a client fetches or
    deletes it; it never expires them on its own. A call site that only polls
    ``status()`` leaks one stored result per call, for the life of the server.
    """

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

    def assertNoStoredResults(self, operation: str) -> None:
        # The server lists 100 results by default; ask for all of them.
        leaked = database_arango.db.async_jobs("done", count=100000)
        self.assertEqual(leaked, [], f"{operation} left unfetched async job results")

    def test_resave_observable_by_value(self) -> None:
        ipv4.IPv4(value="192.0.2.1").save()
        database_arango.db.clear_async_jobs()
        ipv4.IPv4(value="192.0.2.1").save()
        self.assertNoStoredResults("re-saving an existing observable")

    def test_resave_entity_by_name(self) -> None:
        Malware(name="zeus").save()
        database_arango.db.clear_async_jobs()
        Malware(name="zeus").save()
        self.assertNoStoredResults("re-saving an existing entity")

    def test_resave_tag_by_name(self) -> None:
        Tag(name="test").save()
        database_arango.db.clear_async_jobs()
        Tag(name="test").save()
        self.assertNoStoredResults("re-saving an existing tag")

    def test_delete_observable(self) -> None:
        obs = ipv4.IPv4(value="192.0.2.1").save()
        database_arango.db.clear_async_jobs()
        obs.delete()
        self.assertNoStoredResults("deleting an observable")

    def test_swap_link(self) -> None:
        obs1 = ipv4.IPv4(value="192.0.2.1").save()
        obs2 = ipv4.IPv4(value="192.0.2.2").save()
        relationship = obs1.link_to(obs2, "related", "test")
        database_arango.db.clear_async_jobs()
        relationship.swap_link()
        self.assertNoStoredResults("swapping a link")
