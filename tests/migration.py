import os
import time
import unittest

# The migration manager connects without an explicit database name, so mark the
# process as testing before it is imported/instantiated to keep it on the test
# database (test-mode is no longer inferred from `unittest` being imported).
os.environ.setdefault("YETI_TESTING", "1")

from core.migrations import arangodb  # noqa: E402


class ArangoMigrationTest(unittest.TestCase):
    def setUp(self):
        self.migration_manager = arangodb.ArangoMigrationManager()
        self.migration_manager.update_db_version(0)

    def test_migration_init(self):
        self.assertEqual(self.migration_manager.db_version, 0)

    def test_migration_0(self):
        self.migration_manager.migrate_to_latest(stop_at=1)
        self.assertEqual(self.migration_manager.db_version, 1)

    def test_migration_1(self):
        observable_col = self.migration_manager.db.collection("observables")
        observable_col.truncate()
        observable_col.insert(
            {
                "value": "test.com",
                "type": "hostname",
                "root_type": "observable",
                "created": "2024-11-14T11:58:49.757379Z",
            }
        )
        observable_col.insert(
            {
                "value": "test.com123",
                "type": "hostname",
                "root_type": "observable",
                "created": "2024-11-14T11:58:49.757379Z",
            }
        )
        self.migration_manager.migrate_to_latest(stop_at=2)
        self.assertEqual(self.migration_manager.db_version, 2)
        job = observable_col.all()
        while job.status() != "done":
            time.sleep(0.1)
        obs = list(job.result())
        self.assertEqual(len(obs), 2)
        self.assertEqual(obs[0]["value"], "test.com")
        self.assertEqual(obs[0]["is_valid"], True)
        self.assertEqual(obs[1]["value"], "test.com123")
        self.assertEqual(obs[1]["is_valid"], False)
