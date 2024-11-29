import time

from core.database_arango import ASYNC_JOB_WAIT_TIME, ArangoDatabase
from core.migrations import migration


class ArangoMigrationManager(migration.MigrationManager):
    DB_TYPE = "arangodb"

    def connect_to_db(self):
        self.db = ArangoDatabase()
        self.db.connect(check_db_sync=False)

        system_coll = self.db.collection("system")
        job = system_coll.all()
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        migrations = list(job.result())
        if not migrations:
            job = system_coll.insert(
                {"db_version": 0, "db_type": self.DB_TYPE},
            )
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)

            job = system_coll.all()
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            migrations = list(job.result())

        db_version = migrations[0]["db_version"]
        db_type = migrations[0]["db_type"]

        self.db_version = db_version
        self.db_type = db_type

    def update_db_version(self, version: int):
        job = self.db.collection("system").update_match(
            {"db_version": self.db_version, "db_type": self.DB_TYPE},
            {"db_version": version},
        )
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
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
