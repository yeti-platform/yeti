import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import entity, rbac, roles, user
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
        self.user1.link_to_acl(self.group1, roles.Role.OWNER)
        self.user2 = user.UserSensitive(username="user2").save()
        self.user2.link_to_acl(self.group2, roles.Role.OWNER)
        self.admin = user.UserSensitive(username="yeti", admin=True).save()

        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user1.api_key}
        ).json()

        self.user1_token = token_data["access_token"]
        user_token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user2.api_key}
        ).json()
        self.user2_token = user_token_data["access_token"]

        admin_token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.admin.api_key}
        ).json()
        self.admin_token = admin_token_data["access_token"]

    def tearDown(self) -> None:
        rbac.RBAC_ENABLED = False

    def test_create_group(self):
        response = client.post(
            "/api/v2/groups",
            json={"name": "testGroup"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)
        self.assertEqual(data["detail"], "Forbidden: missing global permission 2")

        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/groups",
            json={"name": "testGroup"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
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

    def test_group_search_has_acl(self):
        response = client.post(
            "/api/v2/groups/search",
            json={"name": "test1"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["groups"][0]["name"], "test1")
        acls = data["groups"][0]["acls"]
        self.assertIn("user1", acls)
        self.assertEqual(acls["user1"]["role"], 7)
        self.assertEqual(acls["user1"]["source"], self.user1.extended_id)
        self.assertEqual(acls["user1"]["target"], self.group1.extended_id)

    def test_group_get_details(self):
        response = client.get(
            f"/api/v2/groups/{self.group1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["name"], "test1")
        members = list(data["acls"].keys())
        self.assertEqual(members, ["user1"])

        response = client.get(
            f"/api/v2/groups/{self.group2.id}",
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["name"], "test2")
        members = list(data["acls"].keys())
        self.assertEqual(members, ["user2"])

    def test_admin_has_access_to_all_groups(self):
        response = client.get(
            f"/api/v2/groups/{self.group1.id}",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "test1")
        members = list(data["acls"].keys())
        self.assertEqual(members, ["user1"])

    def test_group_get_details_not_acld(self):
        response = client.get(
            f"/api/v2/groups/{self.group2.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_update_members(self):
        response = client.post(
            f"/api/v2/rbac/group/{self.group1.id}/update-members",
            json={
                "ids": [
                    {"id": self.user2.id, "type": "user"},
                    {"id": self.admin.id, "type": "user"},
                ],
                "role": 4,
            },
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["updated"], 2)
        self.assertEqual(data["failed"], 0)

        response = client.get(
            f"/api/v2/groups/{self.group1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        members = list(data["acls"].keys())
        self.assertCountEqual(members, ["user1", "user2", "yeti"])
