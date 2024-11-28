import unittest

from core.migrations import arangodb


class ArangoMigrationTest(unittest.TestCase):
    def setUp(self):
        self.migration_manager = arangodb.ArangoMigrationManager()
        self.migration_manager.update_db_version(0)

    def test_migration_init(self):
        migration_manager = arangodb.ArangoMigrationManager()
        self.assertEqual(migration_manager.db_version, 0)

    def test_migration_0(self):
        migration_manager = arangodb.ArangoMigrationManager()
        migration_manager.migrate_to_latest(stop_at=1)
        self.assertEqual(migration_manager.db_version, 1)

    def test_migration_1(self):
        migration_manager = arangodb.ArangoMigrationManager()
        observable_col = migration_manager.db.collection("observables")
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
        migration_manager.migrate_to_latest(stop_at=2)
        self.assertEqual(migration_manager.db_version, 2)
        obs = list(observable_col.all())
        self.assertEqual(len(obs), 2)
        self.assertEqual(obs[0]["value"], "test.com")
        self.assertEqual(obs[0]["is_valid"], True)
        self.assertEqual(obs[1]["value"], "test.com123")
        self.assertEqual(obs[1]["is_valid"], False)
