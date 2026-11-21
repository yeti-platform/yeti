import logging
import sys
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class userTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        client.headers = {}
        client.cookies.clear()

    def test_get_config(self) -> None:
        response = client.get("/api/v2/system/config")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("auth", data)
        self.assertIn("system", data)
        self.assertIn("rbac_enabled", data)

    def test_get_config_hides_system_paths_when_unauthenticated(self) -> None:
        from core.config.config import yeti_config

        user = UserSensitive(username="alice", enabled=True).save()
        apikey = user.create_api_key("default")
        token = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()["access_token"]

        orig_get = yeti_config.get

        def fake_get(section, key=None, default=None):
            if section == "auth" and key == "enabled":
                return True
            return orig_get(section, key, default)

        with mock.patch.object(yeti_config, "get", side_effect=fake_get):
            unauth = client.get("/api/v2/system/config")
            self.assertEqual(unauth.status_code, 200)
            self.assertEqual(unauth.json()["system"], {})
            self.assertTrue(unauth.json()["auth"]["enabled"])

            bad_token = client.get(
                "/api/v2/system/config",
                headers={"Authorization": "Bearer not-a-real-token"},
            )
            self.assertEqual(bad_token.status_code, 200)
            self.assertEqual(bad_token.json()["system"], {})

            auth_res = client.get(
                "/api/v2/system/config",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(auth_res.status_code, 200)
            self.assertTrue(auth_res.json()["system"])

            user.enabled = False
            user.save()
            disabled_res = client.get(
                "/api/v2/system/config",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(disabled_res.status_code, 200)
            self.assertEqual(disabled_res.json()["system"], {})


class SystemTypesTest(unittest.TestCase):
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

    def test_get_types(self) -> None:
        response = client.get("/api/v2/system/types")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("observables", data)
        self.assertIn("entities", data)
        self.assertIn("indicators", data)
        self.assertIn("dfiq", data)

        observable_types = {entry["type"] for entry in data["observables"]}
        # These are the exact types issue #1260 reported missing from the
        # frontend's hardcoded dropdown.
        self.assertTrue(
            {"ja3", "jarm", "mutex", "named_pipe", "package"} <= observable_types
        )
        # The family's own base type/aliases must not leak in as entries.
        self.assertNotIn("observable", observable_types)
        self.assertNotIn("observables", observable_types)

        indicator_types = {entry["type"] for entry in data["indicators"]}
        self.assertEqual(
            indicator_types,
            {"forensicartifact", "regex", "query", "yara", "suricata", "sigma"},
        )

        dfiq_types = {entry["type"] for entry in data["dfiq"]}
        self.assertEqual(dfiq_types, {"scenario", "facet", "question"})
        self.assertNotIn("dfiq", dfiq_types)

        # Every entry carries a non-empty label.
        for family in ("observables", "entities", "indicators", "dfiq"):
            for entry in data[family]:
                self.assertTrue(entry["label"])

    def test_get_types_requires_auth(self) -> None:
        client.headers = {}
        response = client.get("/api/v2/system/types")
        self.assertEqual(response.status_code, 401, response.json())


class WorkerStatusTest(unittest.TestCase):
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

    @mock.patch("core.web.apiv2.system.app.control.inspect")
    def test_workers_without_any_worker(self, mock_inspect) -> None:
        """Celery's inspect answers None, not {}, when no worker replies."""
        mock_inspect.return_value.registered.return_value = None
        mock_inspect.return_value.active.return_value = None

        response = client.get("/api/v2/system/workers")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["registered"], {})
        self.assertEqual(data["active"], [])

    @mock.patch("core.web.apiv2.system.app.control.inspect")
    def test_workers_with_a_worker(self, mock_inspect) -> None:
        mock_inspect.return_value.registered.return_value = {
            "worker1@host": ["core.taskscheduler.run_task"]
        }
        mock_inspect.return_value.active.return_value = {
            "worker1@host": [{"args": ["FeedX", "{}"]}]
        }

        response = client.get("/api/v2/system/workers")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(
            data["registered"], {"worker1@host": ["core.taskscheduler.run_task"]}
        )
        self.assertEqual(data["active"], [["FeedX", "{}"]])

    @mock.patch(
        "core.web.apiv2.system.app.control.broadcast",
        return_value=[{"w1": {"ok": "reloading"}}],
    )
    def test_restart_worker_requires_admin(self, mock_broadcast) -> None:
        # Default test user in setUp is non-admin -> 403 even with RBAC off.
        response = client.post("/api/v2/system/restartworker/all")
        self.assertEqual(response.status_code, 403)
        mock_broadcast.assert_not_called()

        admin = UserSensitive(
            username="admin", password="test", enabled=True, admin=True
        ).save()
        admin_apikey = admin.create_api_key("default")
        admin_token = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": admin_apikey}
        ).json()["access_token"]
        response = client.post(
            "/api/v2/system/restartworker/all",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(response.status_code, 200, response.text)
