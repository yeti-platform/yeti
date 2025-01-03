import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import entity, graph, rbac, user
from core.web import webapp

client = TestClient(webapp.app)


class rbacTest(unittest.TestCase):
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
        self.user1.link_to_acl(self.group1, graph.Role.OWNER)
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

    def test_create_group(self):
        response = client.post(
            "/api/v2/groups",
            json={"name": "testGroup"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "testGroup")

    def test_delete_group(self):
        response = client.delete(
            f"/api/v2/groups/{self.group1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_delete_group_not_owner_fails(self):
        response = client.delete(
            f"/api/v2/groups/{self.group1.id}",
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_patch_group(self):
        response = client.patch(
            f"/api/v2/groups/{self.group1.id}",
            json={"rbacgroup": {"name": "test11", "description": "test"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        data = response.json()
        self.assertEqual(data["description"], "test")
        self.assertEqual(data["name"], "test11")
