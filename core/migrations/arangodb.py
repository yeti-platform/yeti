import logging
import time

import tqdm

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

    total_observables = observable.Observable.count()
    logging.info(f"Migrating {total_observables} observables. This may take a while...")
    with tqdm.tqdm(total=total_observables, desc="Migrating observables") as pbar:
        for obs in observable.Observable.list():
            obs.save()
            pbar.update(1)


def migration_2():
    from core.schemas import dfiq, entity, indicator, observable, rbac, roles, user

    OBJECT_TYPES = [
        entity.Entity,
        indicator.Indicator,
        dfiq.DFIQBase,
        observable.Observable,
    ]

    all_users = rbac.Group(
        name="All users", description="Default group for all users"
    ).save()
    admins = rbac.Group(
        name="Admins", description="Default group for all admins"
    ).save()
    for db_user in user.User.list():
        if db_user.admin:
            db_user.link_to_acl(all_users, roles.Role.OWNER)
            db_user.link_to_acl(admins, roles.Role.OWNER)
        else:
            db_user.link_to_acl(all_users, roles.Role.READER)

    for ObjectType in OBJECT_TYPES:
        total_objects = ObjectType.count()
        logging.info(
            f"Updating ACLs for {total_objects} {ObjectType.__name__}. This may take a while..."
        )
        with tqdm.tqdm(
            total=total_objects, desc=f"Updating ACLs for {ObjectType.__name__}"
        ) as pbar:
            for obj in ObjectType.list():
                all_users.link_to_acl(obj, roles.Role.WRITER)
                admins.link_to_acl(obj, roles.Role.OWNER)
                pbar.update(1)


ArangoMigrationManager.register_migration(migration_0)
ArangoMigrationManager.register_migration(migration_1)
ArangoMigrationManager.register_migration(migration_2)

if __name__ == "__main__":
    migration_manager = ArangoMigrationManager()
    migration_manager.migrate_to_latest()
