import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.user import UserSensitive
from core.web import webapp


client = TestClient(webapp.app)

class SimpleGraphTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.clear()
        cls.user1 = UserSensitive(username="tomchop")
        cls.user1.set_password("test")
        cls.user1.save()

    @classmethod
    def tearDownClass(cls) -> None:
        database_arango.db.clear()

    def test_api_not_auth(self) -> None:
        response = client.get("/api/v2/auth/me")
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data['detail'], "Not authenticated")

    def test_api_with_key(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token",
            headers={
                'x-yeti-apikey': self.user1.api_key
            })
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['token_type'], 'bearer')
        self.assertIn('access_token', data)

    def test_api_with_bad_key(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token",
            headers={
                'x-yeti-apikey': 'badkey'
            })
        data = response.json()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(data['detail'], "Invalid API key")

    def test_api_key_bearer(self) -> None:
        response = client.post(
            "/api/v2/auth/api-token",
            headers={
                'x-yeti-apikey': self.user1.api_key
            })
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['token_type'], 'bearer')
        self.assertIn('access_token', data)

        response = client.get(
            "/api/v2/auth/me",
            headers={
                'authorization': f"Bearer {data['access_token']}"
            }
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['username'], 'tomchop')
