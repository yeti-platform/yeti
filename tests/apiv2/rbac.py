import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import entity, rbac, roles, user
from core.web import webapp

client = TestClient(webapp.app)


class rbacTest(unittest.TestCase):
    # mock patch the RBAC_ENABLED global of entities.py
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True

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

        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user2.api_key}
        ).json()
        self.user2_token = token_data["access_token"]

    def tearDown(self) -> None:
        rbac.RBAC_ENABLED = False
        database_arango.RBAC_ENABLED = False

    def test_role_update_unlocks_resource_user(self) -> None:
        """Test that a user can access a resource"""
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
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

        self.user1.link_to_acl(self.group1, roles.Role.OWNER)
        self.group1.link_to_acl(self.entity1, roles.Role.OWNER)

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_different_user_doesnt_have_access(self):
        """Test that a user can access a resource"""
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)

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
        self.user1.link_to_acl(self.entity1, roles.Role.READER)

        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [self.entity1.id], "tags": ["test"]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.entity1, roles.Role.WRITER)

        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [self.entity1.id], "tags": ["test"]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_writer_entity(self):
        """Test that a user can create a new entity"""
        self.user1.global_role = roles.Role.READER
        self.user1.save()

        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)

        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_writer_indicator(self):
        """Test that a user can create a new indicator"""
        self.user1.global_role = roles.Role.READER
        self.user1.save()

        payload = {
            "indicator": {
                "pattern": "test",
                "type": "regex",
                "name": "test",
                "diamond": "victim",
            }
        }
        response = client.post(
            "/api/v2/indicators",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)

        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/indicators",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_writer_observable(self):
        """Test that a user can create a new observable"""
        self.user1.global_role = roles.Role.READER
        self.user1.save()

        payload = {
            "type": "generic",
            "value": "test",
        }

        response = client.post(
            "/api/v2/observables",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)

        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/observables",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_delete_relationship(self):
        """Test that a user can delete a relationship"""
        relationship = self.user1.link_to_acl(self.entity1, roles.Role.OWNER)

        # # assert we can get the entity
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

        # assert entity shows up in search
        response = client.post(
            "/api/v2/entities/search",
            json={"query": {"name": "test1"}, "type": "malware"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["entities"][0]["name"], "test1")

        response = client.delete(
            f"/api/v2/rbac/{relationship.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

        response = client.post(
            "/api/v2/entities/search",
            json={"query": {"name": "test1"}, "type": "malware"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["entities"], [])

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_default_acls(self):
        """Test that a user can create a new entity"""
        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        rbac.Group(name="All users").save()

        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        test_malware = entity.Malware.find(name="test")
        test_malware.get_acls()
        self.assertCountEqual(test_malware.acls.keys(), ["All users", "user1"])
