import collections
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
        # User schema updated
        db_user.save()

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


def migration_3():
    from core.schemas import dfiq, entity, indicator, model, observable, tag

    OBJECT_TYPES = {
        "entities": entity.Entity,
        "indicators": indicator.Indicator,
        "observables": observable.Observable,
    }

    db = ArangoDatabase()
    db.connect(check_db_sync=False)
    job = db.collection("tagged").all()
    while job.status() != "done":
        time.sleep(ASYNC_JOB_WAIT_TIME)
    all_legacy_tags = list(job.result())
    legacy_types_per_source = collections.defaultdict(list)
    resolved = {}
    with tqdm.tqdm(total=len(all_legacy_tags), desc="Aggregating legacy tags") as pbar:
        for tagrel in all_legacy_tags:
            legacy_tag = resolved.get(tagrel["target"])
            if not legacy_tag:
                legacy_tag = tag.Tag.get(tagrel["target"].split("/")[1])
                resolved[tagrel["target"]] = legacy_tag
            tagrel["name"] = legacy_tag.name
            legacy_types_per_source[tagrel["source"]].append(tagrel)
            pbar.update(1)

    logging.info(
        f"Updating {len(all_legacy_tags)} legacy tags. This may take a while..."
    )

    errors = []
    with tqdm.tqdm(
        total=len(legacy_types_per_source), desc="Updating tagged objects"
    ) as pbar:
        for source, tags in legacy_types_per_source.items():
            obj_type, obj_id = source.split("/")

            obj = OBJECT_TYPES[obj_type].get(obj_id)
            if not obj:
                errors.append((source, f"Object not found: {obj_id}"))
                continue
            try:
                newtags = [
                    model.YetiTagInstance(
                        name=t["name"],
                        last_seen=t["last_seen"],
                        expires=t["expires"],
                        fresh=t["fresh"],
                    )
                    for t in tags
                ]
                obj.tags = newtags
                obj.save()
            except Exception as e:
                errors.append((source, str(e)))
                logging.error(f"Error updating {source}: {e}")

            pbar.update(1)

    for source, error in errors:
        logging.error(f"Error updating {source}: {error}")
    logging.info(
        f"Updated {len(legacy_types_per_source) - len(errors)} objects. {len(errors)} errors."
    )


ArangoMigrationManager.register_migration(migration_0)
ArangoMigrationManager.register_migration(migration_1)
ArangoMigrationManager.register_migration(migration_2)
ArangoMigrationManager.register_migration(migration_3)

if __name__ == "__main__":
    migration_manager = ArangoMigrationManager()
    migration_manager.migrate_to_latest()
