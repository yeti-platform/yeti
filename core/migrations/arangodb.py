from core.database_arango import ArangoDatabase
from core.migrations import migration


class ArangoMigrationManager(migration.MigrationManager):
    DB_TYPE = "arangodb"

    def connect_to_db(self):
        self.db = ArangoDatabase()
        self.db.connect()

        system_coll = self.db.collection("system")
        migrations = list(system_coll.all())
        if not migrations:
            system_coll.insert(
                {"db_version": 0, "db_type": self.DB_TYPE},
            )
            migrations = list(system_coll.all())

        db_version = migrations[0]["db_version"]
        db_type = migrations[0]["db_type"]

        self.db_version = db_version
        self.db_type = db_type

    def update_db_version(self, version: int):
        self.db.collection("system").update_match(
            {"db_version": self.db_version, "db_type": self.DB_TYPE},
            {"db_version": version},
        )
        self.db_version = version


def migration_0():
    pass


def migration_1():
    from core.schemas import observable

    for obs in observable.Observable.list():
        obs.save()


ArangoMigrationManager.register_migration(migration_0)
ArangoMigrationManager.register_migration(migration_1)

if __name__ == "__main__":
    migration_manager = ArangoMigrationManager()
    migration_manager.migrate_to_latest()
