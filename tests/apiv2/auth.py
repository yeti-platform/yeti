import logging
import sys
import unittest
from unittest import mock

import httpx
from fastapi import FastAPI
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
EXCHANGE_PATH = "/api/v2/auth/google-access-token"

# The exchange route is only registered on deployments that configure it, so
# these tests serve the handler from an app of their own.
exchange_app = FastAPI()
exchange_app.add_api_route(EXCHANGE_PATH, auth.google_access_token, methods=["POST"])
exchange_client = TestClient(exchange_app)


def _tokeninfo_response(
    claims: dict[str, str] | None = None, status_code: int = 200
) -> httpx.Response:
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
    return httpx.Response(
        status_code,
        json=body,
        request=httpx.Request("POST", auth.GOOGLE_TOKENINFO_URL),
    )


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
        client_ids_patcher = mock.patch.object(
            auth, "GOOGLE_ACCESS_TOKEN_CLIENT_IDS", frozenset({ALLOWED_CLIENT_ID})
        )
        client_ids_patcher.start()
        self.addCleanup(client_ids_patcher.stop)
        tokeninfo_patcher = mock.patch.object(
            httpx.AsyncClient,
            "post",
            new_callable=mock.AsyncMock,
            return_value=_tokeninfo_response(),
        )
        self.mock_post = tokeninfo_patcher.start()
        self.addCleanup(tokeninfo_patcher.stop)

    def _exchange(self) -> httpx.Response:
        return exchange_client.post(EXCHANGE_PATH, json={"access_token": "fake-token"})

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
        self.mock_post.assert_awaited_once_with(
            auth.GOOGLE_TOKENINFO_URL, data={"access_token": "fake-token"}
        )

    def test_tokeninfo_client_settings(self) -> None:
        with mock.patch.object(
            httpx, "AsyncClient", wraps=httpx.AsyncClient
        ) as mock_client_class:
            self._exchange()
        mock_client_class.assert_called_once_with(
            timeout=auth.GOOGLE_TOKENINFO_TIMEOUT_SECONDS,
            verify=auth.GOOGLE_TOKENINFO_SSL_CONTEXT,
        )

    @unittest.skipIf(
        auth.AUTH_MODULE == "oidc" and auth.GOOGLE_ACCESS_TOKEN_CLIENT_IDS,
        "The test configuration enables the exchange endpoint.",
    )
    def test_not_registered_without_configuration(self) -> None:
        response = client.post(EXCHANGE_PATH, json={"access_token": "fake-token"})
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(EXCHANGE_PATH, webapp.app.openapi()["paths"])
        self.mock_post.assert_not_called()

    def test_rejected_claims(self) -> None:
        # Maps each case to the reason that the rejection log line must give.
        cases = {
            "client not allowed": (
                {"azp": "other-client.apps.googleusercontent.com"},
                "is not allowed",
            ),
            "no client": ({"azp": ""}, "is not allowed"),
            "non-identity scope": (
                {"scope": "email https://www.googleapis.com/auth/cloud-platform"},
                "are not identity scopes",
            ),
            "no scope": ({"scope": ""}, "are not identity scopes"),
            "email not verified": (
                {"email_verified": "false"},
                "missing or not verified",
            ),
            "no email": ({"email": ""}, "missing or not verified"),
        }
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, sys.maxsize)
        for name, (claims, reason) in cases.items():
            with self.subTest(name):
                self.mock_post.return_value = _tokeninfo_response(claims)
                with self.assertLogs(auth.logger, logging.INFO) as logs:
                    response = self._exchange()
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["detail"], "Invalid token provided")
                output = "\n".join(logs.output)
                self.assertIn("Rejected access token", output)
                self.assertIn(reason, output)
                self.assertNotIn("fake-token", output)

    def test_token_rejected_by_google(self) -> None:
        self.mock_post.return_value = _tokeninfo_response(status_code=400)
        response = self._exchange()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid token provided")

    def test_google_error(self) -> None:
        self.mock_post.return_value = _tokeninfo_response(status_code=503)
        response = self._exchange()
        self.assertEqual(response.status_code, 503)

    def test_google_invalid_response(self) -> None:
        responses = {
            "not JSON": httpx.Response(200, content=b"<html></html>"),
            "not an object": httpx.Response(200, json=["alice@example.com"]),
        }
        for name, tokeninfo_response in responses.items():
            with self.subTest(name):
                self.mock_post.return_value = tokeninfo_response
                response = self._exchange()
                self.assertEqual(response.status_code, 503)

    def test_google_unreachable(self) -> None:
        errors = {
            "connection error": httpx.ConnectError("unreachable"),
            "timeout": httpx.ReadTimeout("timed out"),
        }
        for name, error in errors.items():
            with self.subTest(name):
                self.mock_post.side_effect = error
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
