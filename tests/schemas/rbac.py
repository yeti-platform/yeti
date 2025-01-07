import unittest

from core import database_arango
from core.schemas import entity, graph, observable, rbac, user


class RBACTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        database_arango.RBAC_ENABLED = True

        self.yeti_user = user.User(username="yeti", admin=True).save()
        self.user1 = user.User(username="test1").save()
        self.user2 = user.User(username="test2").save()
        self.group1 = rbac.Group(name="test1").save()
        self.group2 = rbac.Group(name="test2").save()
        self.entity1 = entity.Malware(name="test1").save()
        self.entity2 = entity.Malware(name="test2").save()
        self.observable1 = observable.Hostname(value="test.com").save()
        self.observable1.link_to(self.entity1, "test", description="test")

    def tearDown(self) -> None:
        database_arango.RBAC_ENABLED = False

    def test_user_group_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.user1.link_to_acl(self.group1, graph.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEqual(role.role, graph.Role.OWNER)
        self.assertEqual(
            role.role,
            graph.Permission.READ | graph.Permission.WRITE | graph.Permission.DELETE,
        )

    def test_group_group_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.group1.link_to_acl(self.group2, graph.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEqual(role.role, graph.Role.OWNER)

    def test_user_entity_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.user1.link_to_acl(self.entity1, graph.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEqual(role.role, graph.Role.OWNER)

    def test_user_has_permissions(self) -> None:
        """Test that a user has a role"""
        self.user1.link_to_acl(self.group1, graph.Role.OWNER)
        has_permissions = self.user1.has_permissions(
            self.group1.extended_id, graph.Role.OWNER
        )
        self.assertTrue(has_permissions)
        has_permissions = self.user1.has_permissions(
            self.group1.extended_id, graph.Role.READER
        )
        self.assertTrue(has_permissions)

    def test_user_has_permissions_on_object(self):
        """Test that a user has a role on an object"""
        self.user1.link_to_acl(self.entity1, graph.Role.OWNER)
        has_permissions = self.user1.has_permissions(
            self.entity1.extended_id, graph.Role.OWNER
        )
        self.assertTrue(has_permissions)
        has_permissions = self.user1.has_permissions(
            self.entity2.extended_id, graph.Role.OWNER
        )
        self.assertFalse(has_permissions)

    def test_user_has_permissions_on_object_via_group(self):
        """Test that a user has a role on an object via a group"""
        self.user1.link_to_acl(self.group1, graph.Role.OWNER)
        self.group1.link_to_acl(self.entity1, graph.Role.OWNER)
        has_permissions = self.user1.has_permissions(
            self.entity1.extended_id, graph.Role.OWNER
        )
        self.assertTrue(has_permissions)
        has_permissions = self.user1.has_permissions(
            self.entity2.extended_id, graph.Role.OWNER
        )
        self.assertFalse(has_permissions)

    def test_filter_entities_with_username_user_acl(self):
        """Test that filter() takes user ACLs into account"""
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 0)
        self.assertEqual(total, 0)

        self.user1.link_to_acl(self.entity1, graph.Role.READER)
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)

    def test_filter_entities_with_username_group_acl(self):
        """Test that filter() takes group ACLs into account"""
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 0)
        self.assertEqual(total, 0)

        self.user1.link_to_acl(self.group1, graph.Role.READER)
        self.group1.link_to_acl(self.entity1, graph.Role.READER)
        entities, total = entity.Entity.filter({}, user=self.user1)
        self.assertEqual(len(entities), 1)
        self.assertEqual(total, 1)

    def test_neighbors_filter_when_passing_username(self):
        """Test that neighbors() takes user ACLs into account"""
        vertices, edges, total = self.observable1.neighbors(user=self.user1)
        self.assertEqual(total, 0)
        self.assertEqual(len(vertices), 0)

        self.user1.link_to_acl(self.entity1, graph.Role.READER)
        vertices, edges, total = self.observable1.neighbors(user=self.user1)
        self.assertEqual(total, 1)
        self.assertEqual(len(vertices), 1)
