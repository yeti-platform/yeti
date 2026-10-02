import logging
import sys
import unittest
from unittest import mock

import requests
from fastapi.testclient import TestClient

from core import database_arango
from core.config.config import yeti_config
from core.schemas.user import UserSensitive
from core.web import webapp
from core.web.apiv2 import auth

SKIP_TESTS = not yeti_config.get("auth", "enabled")

client = TestClient(webapp.app)


class AuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(sys.maxsize)
        auth.YETI_AUTH = True
        auth.AUTH_MODULE = "local"

        database_arango.db.connect(database="yeti_test")
        cls.user1 = UserSensitive(username="tomchop")
        cls.user1.set_password("test")
        cls.user1.save()
        cls.user1_apikey = cls.user1.create_api_key("default")

        cls.user2 = UserSensitive(username="test", enabled=False)
        cls.user2.set_password("test")
        cls.user2.save()
        cls.user2_apikey = cls.user2.create_api_key("default")

    @classmethod
    def tearDownClass(cls) -> None:
        database_arango.db.truncate()
        auth.YETI_AUTH = False

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
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user1_apikey}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["token_type"], "bearer")
        self.assertIn("access_token", data)

    def test_api_with_disabled_user(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user2_apikey}
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
        self.assertEqual(data["detail"], "Could not validate credentials")

    def test_api_key_used_directly_as_bearer(self) -> None:
        """A CLI-generated API key has no expiration. Used directly as a raw
        Bearer token (bypassing the /api-token exchange), it must not crash
        the server -- its JWT has no exp claim at all rather than a null
        one, so PyJWT's expiration check is skipped instead of erroring."""
        response = client.get(
            "/api/v2/auth/me",
            headers={"authorization": f"Bearer {self.user1_apikey}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["username"], "tomchop")

    def test_api_key_bearer(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": self.user1_apikey}
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


ALLOWED_CLIENT_ID = "allowed-client.apps.googleusercontent.com"


def _tokeninfo_response(
    claims: dict[str, str] | None = None, status_code: int = 200
) -> mock.Mock:
    """Returns a fake response from Google's tokeninfo endpoint.

    Args:
        claims: Claims that replace or add to those of a valid token.
        status_code: HTTP status of the response.
    """
    body = {
        "azp": ALLOWED_CLIENT_ID,
        "aud": ALLOWED_CLIENT_ID,
        "email": "alice@example.com",
        "email_verified": "true",
        "scope": "email https://www.googleapis.com/auth/userinfo.email",
        "expires_in": "3599",
    }
    body.update(claims or {})
    response = mock.Mock(status_code=status_code)
    response.json.return_value = body
    return response


class GoogleAccessTokenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        UserSensitive(username="alice@example.com").save()
        UserSensitive(username="bob@example.com", enabled=False).save()

    @classmethod
    def tearDownClass(cls) -> None:
        database_arango.db.truncate()

    def setUp(self) -> None:
        for patcher in (
            mock.patch.object(auth, "AUTH_MODULE", "oidc"),
            mock.patch.object(
                auth, "GOOGLE_ACCESS_TOKEN_CLIENT_IDS", frozenset({ALLOWED_CLIENT_ID})
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        tokeninfo_patcher = mock.patch.object(
            auth.requests, "post", return_value=_tokeninfo_response()
        )
        self.mock_post = tokeninfo_patcher.start()
        self.addCleanup(tokeninfo_patcher.stop)

    def _exchange(self):
        return client.post(
            "/api/v2/auth/google-access-token", json={"access_token": "fake-token"}
        )

    def test_exchange(self) -> None:
        response = self._exchange()
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["token_type"], "bearer")

        response = client.get(
            "/api/v2/auth/me",
            headers={"authorization": f"Bearer {data['access_token']}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], "alice@example.com")

    def test_token_sent_in_form_body(self) -> None:
        self._exchange()
        self.mock_post.assert_called_once_with(
            auth.GOOGLE_TOKENINFO_URL,
            data={"access_token": "fake-token"},
            timeout=auth.GOOGLE_TOKENINFO_TIMEOUT_SECONDS,
        )

    def test_disabled_without_client_ids(self) -> None:
        with mock.patch.object(auth, "GOOGLE_ACCESS_TOKEN_CLIENT_IDS", frozenset()):
            response = self._exchange()
        self.assertEqual(response.status_code, 404)
        self.mock_post.assert_not_called()

    def test_disabled_with_local_auth(self) -> None:
        with mock.patch.object(auth, "AUTH_MODULE", "local"):
            response = self._exchange()
        self.assertEqual(response.status_code, 404)
        self.mock_post.assert_not_called()

    def test_rejected_claims(self) -> None:
        cases = {
            "client not allowed": {"azp": "other-client.apps.googleusercontent.com"},
            "no client": {"azp": ""},
            "non-identity scope": {
                "scope": "email https://www.googleapis.com/auth/cloud-platform"
            },
            "no scope": {"scope": ""},
            "email not verified": {"email_verified": "false"},
            "no email": {"email": ""},
        }
        for name, claims in cases.items():
            with self.subTest(name):
                self.mock_post.return_value = _tokeninfo_response(claims)
                response = self._exchange()
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["detail"], "Invalid token provided")

    def test_token_rejected_by_google(self) -> None:
        self.mock_post.return_value = _tokeninfo_response(status_code=400)
        response = self._exchange()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid token provided")

    def test_google_error(self) -> None:
        self.mock_post.return_value = _tokeninfo_response(status_code=503)
        response = self._exchange()
        self.assertEqual(response.status_code, 503)

    def test_google_unreachable(self) -> None:
        self.mock_post.side_effect = requests.ConnectionError("unreachable")
        response = self._exchange()
        self.assertEqual(response.status_code, 503)

    def test_unknown_user(self) -> None:
        self.mock_post.return_value = _tokeninfo_response(
            {"email": "carol@example.com"}
        )
        response = self._exchange()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json()["detail"], "Invalid user. Please contact your server admin."
        )

    def test_disabled_user(self) -> None:
        self.mock_post.return_value = _tokeninfo_response({"email": "bob@example.com"})
        response = self._exchange()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json()["detail"],
            "User account disabled. Please contact your server admin.",
        )
