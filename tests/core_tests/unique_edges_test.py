import concurrent.futures
import logging
import os
import threading
import unittest
from unittest import mock

# migration_4 connects without naming a database; keep it on the test one.
os.environ.setdefault("YETI_TESTING", "1")

from arango.exceptions import AQLQueryExecuteError, IndexCreateError  # noqa: E402

from core import database_arango  # noqa: E402
from core.migrations import arangodb  # noqa: E402
from core.schemas import entity, observable, rbac, roles, user  # noqa: E402
from core.schemas.graph import Relationship  # noqa: E402

UNIQUE = database_arango.ArangoDatabase.UNIQUE_EDGE_INDEXES


def unique_index(collection: str) -> dict | None:
    name, _ = UNIQUE[collection]
    for index in database_arango.db.db.collection(collection).indexes():
        if index.get("name") == name:
            return index
    return None


def drop_unique_index(collection: str) -> None:
    index = unique_index(collection)
    if index:
        database_arango.db.db.collection(collection).delete_index(index["id"])


def unique_violation() -> AQLQueryExecuteError:
    error = AQLQueryExecuteError.__new__(AQLQueryExecuteError)
    error.error_code = database_arango.ARANGO_UNIQUE_CONSTRAINT_ERROR_CODE
    return error


class UniqueEdgeTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.addCleanup(self.restore_indexes)
        self.user = user.User(username="alice").save()
        self.group = rbac.Group(name="analysts").save()
        self.hostname = observable.save(type="hostname", value="evil.example.com")
        self.malware = entity.Malware(name="evilware").save()

    def restore_indexes(self) -> None:
        for collection in UNIQUE:
            database_arango.db.db.collection(collection).truncate()
        database_arango.db.ensure_unique_edge_indexes(strict=True)

    def edge(self, src: str, dst: str, **fields) -> dict:
        return {"_from": src, "_to": dst, "source": src, "target": dst, **fields}

    def test_connect_creates_the_unique_indexes(self) -> None:
        for collection, (_, fields) in UNIQUE.items():
            index = unique_index(collection)
            self.assertIsNotNone(index, collection)
            assert index is not None
            self.assertTrue(index["unique"])
            self.assertEqual(index["fields"], fields)

    def test_concurrent_link_to_collapses_into_one_edge_with_full_count(self) -> None:
        calls = 32
        # Released together: a pool otherwise starts its threads one by
        # one, and calls that never overlap can't exercise the race.
        gate = threading.Barrier(calls)

        def link(_):
            gate.wait()
            self.hostname.link_to(self.malware, "uses", "c2")

        with concurrent.futures.ThreadPoolExecutor(max_workers=calls) as executor:
            list(executor.map(link, range(calls)))

        edges = [
            r
            for r in Relationship.list()
            if r.source == self.hostname.extended_id and r.type == "uses"
        ]
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].count, calls)

    @mock.patch.object(database_arango.time, "sleep")
    def test_unique_violation_is_retried_only_when_asked(self, _sleep) -> None:
        fake_db = mock.Mock()
        fake_db.aql.execute.side_effect = [unique_violation(), "cursor"]
        result = database_arango.execute_aql_with_conflict_retry(
            fake_db, "UPSERT ...", {}, retry_on_unique_violation=True
        )
        self.assertEqual(result, "cursor")
        self.assertEqual(fake_db.aql.execute.call_count, 2)

        fake_db = mock.Mock()
        fake_db.aql.execute.side_effect = [unique_violation(), "cursor"]
        with self.assertRaises(AQLQueryExecuteError):
            database_arango.execute_aql_with_conflict_retry(fake_db, "UPSERT ...", {})
        self.assertEqual(fake_db.aql.execute.call_count, 1)

    def test_existing_duplicates_warn_on_connect_and_fail_strictly(self) -> None:
        drop_unique_index("acls")
        duplicate = self.edge(
            self.user.extended_id, self.group.extended_id, role=int(roles.Role.READER)
        )
        database_arango.db.db.collection("acls").insert_many([duplicate, duplicate])

        previous = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous)
        with self.assertLogs(level=logging.WARNING) as logs:
            database_arango.db.ensure_unique_edge_indexes(strict=False)
        self.assertIn("migrate-arangodb", "\n".join(logs.output))
        self.assertIsNone(unique_index("acls"))

        with self.assertRaises(IndexCreateError):
            database_arango.db.ensure_unique_edge_indexes(strict=True)

    def test_migration_4_merges_duplicates_and_adds_the_indexes(self) -> None:
        for collection in UNIQUE:
            drop_unique_index(collection)
        member, other = self.user.extended_id, self.group.extended_id
        database_arango.db.db.collection("acls").insert_many(
            [
                self.edge(
                    member,
                    other,
                    role=int(roles.Role.READER),
                    created="2026-01-01T00:00:00+00:00",
                    modified="2026-01-01T00:00:00+00:00",
                ),
                self.edge(
                    member,
                    other,
                    role=int(roles.Role.OWNER),
                    created="2026-01-02T00:00:00+00:00",
                    modified="2026-03-01T00:00:00+00:00",
                ),
            ]
        )
        src, dst = self.hostname.extended_id, self.malware.extended_id
        database_arango.db.db.collection("links").insert_many(
            [
                self.edge(
                    src,
                    dst,
                    type="uses",
                    count=2,
                    description="older",
                    created="2026-02-01T00:00:00+00:00",
                    modified="2026-02-01T00:00:00+00:00",
                ),
                self.edge(
                    src,
                    dst,
                    type="uses",
                    count=3,
                    description="newer",
                    created="2026-01-15T00:00:00+00:00",
                    modified="2026-04-01T00:00:00+00:00",
                ),
                # Same endpoints, different type: a separate link, not a duplicate.
                self.edge(
                    src,
                    dst,
                    type="targets",
                    count=7,
                    description="other",
                    created="2026-01-01T00:00:00+00:00",
                    modified="2026-01-01T00:00:00+00:00",
                ),
            ]
        )

        arangodb.migration_4()

        acls = list(database_arango.db.db.collection("acls").all())
        self.assertEqual(len(acls), 1)
        self.assertEqual(acls[0]["role"], int(roles.Role.OWNER))

        links = {e["type"]: e for e in database_arango.db.db.collection("links").all()}
        self.assertEqual(sorted(links), ["targets", "uses"])
        self.assertEqual(links["uses"]["count"], 5)
        self.assertEqual(links["uses"]["description"], "newer")
        self.assertEqual(links["uses"]["created"], "2026-01-15T00:00:00+00:00")
        self.assertEqual(links["targets"]["count"], 7)

        for collection in UNIQUE:
            self.assertIsNotNone(unique_index(collection), collection)
