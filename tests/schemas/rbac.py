import unittest

from core import database_arango
from core.schemas import entity, graph, rbac, user


class TagTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.user1 = user.User(username="test1").save()
        self.user2 = user.User(username="test2").save()
        self.group1 = rbac.Group(name="test1").save()
        self.group2 = rbac.Group(name="test2").save()
        self.entity1 = entity.Malware(name="test1").save()
        self.entity2 = entity.Malware(name="test2").save()

    def test_user_group_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.user1.link_to_acl(self.group1, graph.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEquals(role.role, "owner")

    def test_group_group_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.group1.link_to_acl(self.group2, graph.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEqual(role.role, "owner")

    def test_user_entity_role_association(self) -> None:
        """Test that a role can be created"""
        role = self.user1.link_to_acl(self.entity1, graph.Role.OWNER)
        self.assertIsNotNone(role.id)
        self.assertEquals(role.role, "owner")

    def test_user_has_role(self) -> None:
        """Test that a user has a role"""
        self.user1.link_to_acl(self.group1, graph.Role.OWNER)
        has_role = self.user1.has_role(self.group1.extended_id, graph.Role.OWNER)
        self.assertTrue(has_role)
        has_role = self.user1.has_role(self.group1.extended_id, graph.Role.READ)
        self.assertFalse(has_role)

    def test_user_has_role_on_object(self):
        """Test that a user has a role on an object"""
        self.user1.link_to_acl(self.entity1, graph.Role.OWNER)
        has_role = self.user1.has_role(self.entity1.extended_id, graph.Role.OWNER)
        self.assertTrue(has_role)
        has_role = self.user1.has_role(self.entity2.extended_id, graph.Role.OWNER)
        self.assertFalse(has_role)

    def test_user_has_role_on_object_via_group(self):
        """Test that a user has a role on an object via a group"""
        self.user1.link_to_acl(self.group1, graph.Role.OWNER)
        self.group1.link_to_acl(self.entity1, graph.Role.OWNER)
        has_role = self.user1.has_role(self.entity1.extended_id, graph.Role.OWNER)
        self.assertTrue(has_role)
        has_role = self.user1.has_role(self.entity2.extended_id, graph.Role.OWNER)
        self.assertFalse(has_role)
