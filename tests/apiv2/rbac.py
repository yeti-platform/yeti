import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import entity, graph, rbac, user
from core.web import webapp

client = TestClient(webapp.app)


class rbacTest(unittest.TestCase):
    # mock patch the RBAC_ENABLED global of entities.py
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        rbac.RBAC_ENABLED = True

        self.group1 = rbac.Group(name="test1").save()
        self.group2 = rbac.Group(name="test2").save()
        self.entity1 = entity.Malware(name="test1").save()
        self.entity2 = entity.Malware(name="test2").save()

        self.user1 = user.UserSensitive(username="user1").save()
        self.user2 = user.UserSensitive(username="user2").save()
        self.admin = user.UserSensitive(username="yeti", admin=True).save()

        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user1.api_key}
        ).json()

        self.user1_token = token_data["access_token"]
        user_token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user2.api_key}
        ).json()
        self.user2_token = user_token_data["access_token"]

    def tearDown(self) -> None:
        rbac.RBAC_ENABLED = False

    def test_role_update_unlocks_resource_user(self) -> None:
        """Test that a user can access a resource"""
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.entity1, graph.Role.OWNER)
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_role_update_unlocks_resource_via_group(self) -> None:
        """Test that a user can access a resource"""
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.group1, graph.Role.OWNER)
        self.group1.link_to_acl(self.entity1, graph.Role.OWNER)

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_different_user_doesnt_have_access(self):
        """Test that a user can access a resource"""
        self.user1.link_to_acl(self.entity1, graph.Role.OWNER)

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_user_can_tag_entity(self):
        """Test that a user can tag an entity"""
        self.user1.link_to_acl(self.entity1, graph.Role.READER)

        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [self.entity1.id], "tags": ["test"]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.entity1, graph.Role.WRITER)

        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [self.entity1.id], "tags": ["test"]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_reader(self):
        """Test that a user can access a resource"""
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.global_role = graph.Role.READER
        self.user1.save()

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_writer(self):
        """Test that a user can create a new entity"""
        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)

        self.user1.global_role = graph.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)