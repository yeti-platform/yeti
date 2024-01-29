import logging
import sys
import unittest

from core import database_arango
from core.schemas.user import UserSensitive
from core.web import webapp
from fastapi.testclient import TestClient

client = TestClient(webapp.app)


class userTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.admin = UserSensitive(username="admin", admin=True).save()
        self.user = UserSensitive(username="tomchop", admin=False).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.admin.api_key}
        ).json()
        self.admin_token = token_data["access_token"]
        user_token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user.api_key}
        ).json()
        self.user_token = user_token_data["access_token"]

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_search_users(self):
        response = client.post(
            "/api/v2/users/search",
            json={"username": "tomch"},
            headers={"Authorization": f"Bearer {self.user_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(data)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["users"][0]["username"], "tomchop")

    def test_toggle_user_admin(self):
        response = client.post(
            "/api/v2/users/toggle",
            json={"user_id": self.user.id, "field": "enabled"},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data)
        self.assertEqual(data["username"], "tomchop")
        self.assertEqual(data["enabled"], False)
        self.assertEqual(data["admin"], False)

        response = client.post(
            "/api/v2/users/toggle",
            json={"user_id": self.user.id, "field": "admin"},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        data = response.json()

        self.assertEqual(data["enabled"], False)
        self.assertEqual(data["admin"], True)

    def test_toggle_user_unprivileged(self):
        response = client.post(
            "/api/v2/users/toggle",
            json={"user_id": self.admin.id, "field": "enabled"},
            headers={"Authorization": f"Bearer {self.user_token}"},
        )

        data = response.json()
        self.assertEqual(response.status_code, 401, data)
        self.assertIsNotNone(data)
        self.assertEqual(data["detail"], "user tomchop is not an admin")

    def test_toggle_user_self(self):
        response = client.post(
            "/api/v2/users/toggle",
            json={"user_id": self.admin.id, "field": "enabled"},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )

        data = response.json()
        self.assertEqual(response.status_code, 400, data)
        self.assertIsNotNone(data)
        self.assertEqual(data["detail"], "cannot toggle own user (admin)")

    def test_reset_api_key(self):
        response = client.post(
            "/api/v2/users/reset-api-key",
            json={"user_id": self.user.id},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data)
        self.assertNotEqual(data["api_key"], self.user.api_key)
        self.assertEqual(data["username"], "tomchop")

    def test_reset_own_password(self):
        response = client.post(
            "/api/v2/users/reset-password",
            json={"user_id": self.user.id, "new_password": "newpassword"},
            headers={"Authorization": f"Bearer {self.user_token}"},
        )

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data)
        self.assertEqual(data["username"], "tomchop")
        self.assertTrue(UserSensitive.get(self.user.id).verify_password("newpassword"))

    def test_reset_password_unprivileged(self):
        response = client.post(
            "/api/v2/users/reset-password",
            json={"user_id": self.admin.id, "new_password": "newpassword"},
            headers={"Authorization": f"Bearer {self.user_token}"},
        )

        data = response.json()
        self.assertEqual(response.status_code, 401, data)
        self.assertIsNotNone(data)
        self.assertEqual(data["detail"], "cannot reset password for other users")

    def test_rest_password_admin(self):
        response = client.post(
            "/api/v2/users/reset-password",
            json={"user_id": self.user.id, "new_password": "newpassword"},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data)
        self.assertEqual(data["username"], "tomchop")
        self.assertTrue(UserSensitive.get(self.user.id).verify_password("newpassword"))

    def test_delete_user(self):
        user_in_db = UserSensitive.get(self.user.id)
        assert user_in_db is not None
        self.assertEqual(user_in_db.username, "tomchop")

        response = client.delete(
            f"/api/v2/users/{self.user.id}",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        response.json()
        self.assertEqual(response.status_code, 200)

        user_in_db = UserSensitive.get(self.user.id)
        self.assertIsNone(user_in_db)

    def test_delete_user_unprivileged(self):
        response = client.delete(
            f"/api/v2/users/{self.admin.id}",
            headers={"Authorization": f"Bearer {self.user_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 401)
        self.assertIsNotNone(data)
        self.assertEqual(data["detail"], "user tomchop is not an admin")

    def test_create_user(self):
        response = client.post(
            "/api/v2/users/",
            json={"username": "newuser", "password": "password", "admin": False},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(data)
        self.assertEqual(data["username"], "newuser")
        self.assertEqual(data["admin"], False)

        user = UserSensitive.get(data["id"])
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "newuser")
