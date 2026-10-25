import logging
import sys
import unittest

from click.testing import CliRunner

from core import database_arango
from core.schemas import rbac, roles
from core.schemas.user import UserSensitive
from yetictl.cli import create_user


class CliCreateUserGroupsTest(unittest.TestCase):
    """`create-user` must put new users in the same default groups the API does,
    otherwise a CLI-provisioned user has no ACL path to anything and sees an
    empty platform once RBAC is enabled."""

    def setUp(self) -> None:
        # logging.disable() is process-global and sticky, so restore whatever it
        # was afterwards: leaving it on breaks every assertLogs() test that runs
        # later in the same pytest process.
        previous = logging.root.manager.disable
        logging.disable(sys.maxsize)
        self.addCleanup(logging.disable, previous)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.runner = CliRunner()

    def invoke(self, *args) -> None:
        result = self.runner.invoke(create_user, list(args))
        self.assertEqual(result.exit_code, 0, result.output)

    def test_new_user_reads_all_users(self) -> None:
        self.invoke("analyst", "password")

        user = UserSensitive.find(username="analyst")
        all_users = rbac.Group.find(name="All users")
        self.assertIsNotNone(all_users, "the All users group should have been created")
        self.assertTrue(
            user.has_permissions(all_users.extended_id, roles.Permission.READ)
        )
        # READER, not OWNER: a plain user does not get to delete the group.
        self.assertFalse(
            user.has_permissions(all_users.extended_id, roles.Permission.DELETE)
        )

    def test_new_admin_owns_both_default_groups(self) -> None:
        self.invoke("boss", "password", "--admin")

        user = UserSensitive.find(username="boss")
        admins = rbac.Group.find(name="Admins")
        all_users = rbac.Group.find(name="All users")
        self.assertIsNotNone(admins, "the Admins group should have been created")
        self.assertTrue(
            user.has_permissions(admins.extended_id, roles.Permission.DELETE)
        )
        self.assertTrue(
            user.has_permissions(all_users.extended_id, roles.Permission.DELETE)
        )

    def test_existing_groups_are_reused(self) -> None:
        existing = rbac.Group(name="All users").save()

        self.invoke("analyst", "password")

        _, total = rbac.Group.filter(
            query_args={"name": "All users"}, offset=0, count=10
        )
        self.assertEqual(total, 1, "a second All users group was created")
        user = UserSensitive.find(username="analyst")
        self.assertTrue(
            user.has_permissions(existing.extended_id, roles.Permission.READ)
        )


if __name__ == "__main__":
    unittest.main()
