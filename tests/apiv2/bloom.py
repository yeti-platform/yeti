import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class IndicatorTest(unittest.TestCase):
    def setUp(self) -> None:
        user = UserSensitive(username="test", password="test", enabled=True).save()
        apikey = user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    def testConnectionError(self) -> None:
        response = client.post(
            "/api/v2/bloom/search",
            json={
                "values": ["test"],
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 503, data)
        self.assertIn("Error connecting to bloomcheck", data["detail"])

    @mock.patch("core.web.apiv2.bloom.requests.post")
    def testBloomCall(self, mock_post) -> None:
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"value": "test", "hits": ["fltr"]}]
        mock_post.return_value = mock_response

        response = client.post(
            "/api/v2/bloom/search",
            json={
                "values": ["test"],
            },
        )

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["value"], "test")

        mock_post.assert_called_once_with(
            "http://bloomcheck:8100/check",
            json={"values": ["test"], "filters": []},
        )

    @mock.patch("core.web.apiv2.bloom.requests.post")
    def testBloomCallRaw(self, mock_post) -> None:
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"value": "test", "hits": ["fltr"]}]
        mock_post.return_value = mock_response
        test_body = b"test1\ntest2\ntest3\n"
        response = client.post("/api/v2/bloom/search/raw", data=test_body)

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["value"], "test")

        mock_post.assert_called_once_with(
            "http://bloomcheck:8100/check/raw",
            data=b"test1\ntest2\ntest3\n",
        )
