import logging
import sys
import unittest

from core import database_arango
from core.config.config import yeti_config
from core.schemas.user import UserSensitive
from core.web import webapp
from fastapi.testclient import TestClient

SKIP_TESTS = not yeti_config.get("auth", "enabled")

client = TestClient(webapp.app)


@unittest.skipIf(SKIP_TESTS, "Auth is disabled")
class AuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.clear()
        cls.user1 = UserSensitive(username="tomchop")
        cls.user1.set_password("test")
        cls.user1.save()

        cls.user2 = UserSensitive(username="test", enabled=False)
        cls.user2.set_password("test")
        cls.user2.save()

    @classmethod
    def tearDownClass(cls) -> None:
        database_arango.db.clear()

    def test_login(self) -> None:
        response = client.post(
            "/api/v2/auth/token", data={"username": "tomchop", "password": "test"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["token_type"], "bearer")
        # test that cookie is also set
        self.assertIn("set-cookie", response.headers)
        self.assertIn("yeti_session", response.headers["set-cookie"])
        self.assertIn(data["access_token"], response.headers["set-cookie"])

    def test_login_nonexistent(self) -> None:
        response = client.post(
            "/api/v2/auth/token", data={"username": "nope", "password": "test"}
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data["detail"], "Incorrect username or password")

    def test_login_disabled(self) -> None:
        response = client.post(
            "/api/v2/auth/token", data={"username": "test", "password": "test"}
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(
            data["detail"], "User account disabled. Please contact your server admin."
        )

    def test_cookie_auth(self) -> None:
        response = client.post(
            "/api/v2/auth/token", data={"username": "tomchop", "password": "test"}
        )
        data = response.json()
        token = data["access_token"]

        response = client.get(
            "/api/v2/auth/me", headers={"cookie": "yeti_session=" + token}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["username"], "tomchop")

    def test_api_not_auth(self) -> None:
        response = client.get("/api/v2/auth/me")
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data["detail"], "Could not validate credentials")

    def test_api_with_key(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user1.api_key}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["token_type"], "bearer")
        self.assertIn("access_token", data)

    def test_api_with_disabled_user(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user2.api_key}
        )
        data = response.json()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            data["detail"], "User account disabled. Please contact your server admin."
        )

    def test_api_with_bad_key(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": "badkey"}
        )
        data = response.json()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(data["detail"], "Invalid API key")

    def test_api_key_bearer(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user1.api_key}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["token_type"], "bearer")
        self.assertIn("access_token", data)

        response = client.get(
            "/api/v2/auth/me",
            headers={"authorization": f"Bearer {data['access_token']}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["username"], "tomchop")

    def test_logout(self) -> None:
        response = client.post(
            "/api/v2/auth/token", data={"username": "tomchop", "password": "test"}
        )
        data = response.json()
        token = data["access_token"]

        response = client.get(
            "/api/v2/auth/me", headers={"cookie": "yeti_session=" + token}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["username"], "tomchop")

        response = client.post(
            "/api/v2/auth/logout", headers={"cookie": "yeti_session=" + token}
        )
        self.assertEqual(response.status_code, 200)

        response = client.get(
            "/api/v2/auth/me", headers={"cookie": "yeti_session=" + token}
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data["detail"], "Could not validate credentials")
