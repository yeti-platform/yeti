import logging
import sys
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class AgentsProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

        user = UserSensitive(username="test", password="test", enabled=True).save()
        apikey = user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    @mock.patch("core.web.apiv2.agents.httpx.Client")
    def test_list_sessions_forwards_create_time_and_title(self, mock_client_cls):
        """The proxy's ADKSession model must not silently drop fields the
        agent service sends -- createTime/title used to vanish here even
        though the agent service already returned them, because this
        model didn't declare them.
        """
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "session-1",
                "appName": "yeti_agents",
                "userId": "test",
                "lastUpdateTime": 100.0,
                "createTime": 90.0,
                "title": "What can you tell me about Sandworm Team?",
            }
        ]
        mock_client_cls.return_value.__enter__.return_value.get.return_value = (
            mock_response
        )

        response = client.get("/api/v2/agents/sessions")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()

        self.assertEqual(data[0]["createTime"], 90.0)
        self.assertEqual(data[0]["title"], "What can you tell me about Sandworm Team?")

    @mock.patch("core.web.apiv2.agents.httpx.Client")
    def test_list_sessions_tolerates_missing_create_time_and_title(
        self, mock_client_cls
    ):
        """Older sessions predating this feature have no metadata recorded
        for them -- the proxy must not choke on their absence.
        """
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "session-1",
                "appName": "yeti_agents",
                "userId": "test",
                "lastUpdateTime": 100.0,
            }
        ]
        mock_client_cls.return_value.__enter__.return_value.get.return_value = (
            mock_response
        )

        response = client.get("/api/v2/agents/sessions")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()

        self.assertIsNone(data[0]["createTime"])
        self.assertIsNone(data[0]["title"])
