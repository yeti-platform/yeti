import unittest

from core import database_arango
from core.schemas import entity, observable, rbac, roles, user


class RBACTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        database_arango.RBAC_ENABLED = True

        self.yeti_user = user.User(username="yeti", admin=True).save()
        self.user1 = user.User(username="user1").save()
        self.user2 = user.User(username="user2").save()
        self.group1 = rbac.Group(name="group1").save()
        self.group2 = rbac.Group(name="group2").save()
        self.entity1 = entity.Malware(name="malware1").save()
        self.entity2 = entity.Malware(name="malware2").save()
        self.observable1 = observable.Hostname(value="test.com").save()
        self.observable1.link_to(self.entity1, "test", description="test")

    def tearDown(self) -> None:
        database_arango.RBAC_ENABLED = False

    def test_user_group_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.user1.link_to_acl(self.group1, roles.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEqual(role.role, roles.Role.OWNER)
        self.assertEqual(
            role.role,
            roles.Permission.READ | roles.Permission.WRITE | roles.Permission.DELETE,
        )

    def test_group_group_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.group1.link_to_acl(self.group2, roles.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEqual(role.role, roles.Role.OWNER)

    def test_user_entity_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEqual(role.role, roles.Role.OWNER)

    def test_user_has_permissions(self) -> None:
        """Test that a user has a role"""
        self.user1.link_to_acl(self.group1, roles.Role.OWNER)
        has_permissions = self.user1.has_permissions(
            self.group1.extended_id, roles.Role.OWNER
        )
        self.assertTrue(has_permissions)
        has_permissions = self.user1.has_permissions(
            self.group1.extended_id, roles.Role.READER
        )
        self.assertTrue(has_permissions)

    def test_user_has_permissions_on_object(self):
        """Test that a user has a role on an object"""
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
        has_permissions = self.user1.has_permissions(
            self.entity1.extended_id, roles.Role.OWNER
        )
        self.assertTrue(has_permissions)
        has_permissions = self.user1.has_permissions(
            self.entity2.extended_id, roles.Role.OWNER
        )
        self.assertFalse(has_permissions)

    def test_user_has_permissions_on_object_via_group(self):
        """Test that a user has a role on an object via a group"""
        self.user1.link_to_acl(self.group1, roles.Role.OWNER)
        self.group1.link_to_acl(self.entity1, roles.Role.OWNER)
        has_permissions = self.user1.has_permissions(
            self.entity1.extended_id, roles.Role.OWNER
        )
        self.assertTrue(has_permissions)
        has_permissions = self.user1.has_permissions(
            self.entity2.extended_id, roles.Role.OWNER
        )
        self.assertFalse(has_permissions)

    def test_filter_entities_with_username_user_acl(self):
        """Test that filter() takes user ACLs into account"""
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 0)
        self.assertEqual(total, 0)

        self.user1.link_to_acl(self.entity1, roles.Role.READER)
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)

    def test_filter_entities_with_username_group_acl(self):
        """Test that filter() takes group ACLs into account"""
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 0)
        self.assertEqual(total, 0)

        self.user1.link_to_acl(self.group1, roles.Role.READER)
        self.group1.link_to_acl(self.entity1, roles.Role.READER)
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)

    def test_neighbors_filter_when_passing_username(self):
        """Test that neighbors() takes user ACLs into account"""
        vertices, edges, total = self.observable1.neighbors(user=self.user1)
        self.assertEqual(total, 0)
        self.assertEqual(len(vertices), 0)

        self.user1.link_to_acl(self.entity1, roles.Role.READER)
        vertices, edges, total = self.observable1.neighbors(user=self.user1)
        self.assertEqual(total, 1)
        self.assertEqual(len(vertices), 1)

    def test_get_acls(self):
        """Test that get_acls() returns the correct ACLs"""
        self.user1.link_to_acl(self.group1, roles.Role.OWNER)
        self.group1.link_to_acl(self.entity1, roles.Role.OWNER)
        self.entity1.get_acls()
        self.assertEqual(len(self.entity1._acls), 2)
        self.assertIn(self.group1.name, self.entity1._acls)
        self.assertIn(self.user1.username, self.entity1._acls)
