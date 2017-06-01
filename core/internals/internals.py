import pkgutil
import importlib
import logging

from mongoengine import *

from core.database import YetiDocument
from core.constants import DB_VERSION
from core.constants import MIGRATIONS_DIRECTORY

class Internals(YetiDocument):
    db_version = IntField(default=0)
    name = StringField(default="default", unique=True)
    __internal = None

    @classmethod
    def syncdb(klass):
        current_version = klass.get_internals().db_version
        if DB_VERSION > current_version:
            print "[+] Database version outdated: {} vs. {}".format(current_version, DB_VERSION)
            klass.apply_migrations(current_version, DB_VERSION)
        else:
            print "[+] Database version is synced with code."

    @classmethod
    def get_internals(klass):
        if klass.__internal is None:
            klass.__internal = Internals.get_or_create(name="default")
        return klass.__internal

    @classmethod
    def apply_migrations(klass, current_version, target_version):
        print "    Applying migrations..."
        print "    Current version: {}".format(current_version)
        print "    Syncing to version: {}".format(target_version)
        internal_version = current_version

        migrations = pkgutil.walk_packages([MIGRATIONS_DIRECTORY], prefix=".")

        for loader, name, ispkg in sorted(migrations, key=lambda m: int(m[1].split("_")[1])):
            migration_version = int(name.split("_")[1])
            if internal_version < target_version and migration_version <= target_version:
                print "        * Migrating database: {} -> {}".format(current_version, migration_version)
                migration = importlib.import_module(name, package='core.internals.migrations')
                migration.migrate()
                klass.__internal.db_version = migration_version
                klass.__internal.save()
                internal_version = migration_version
