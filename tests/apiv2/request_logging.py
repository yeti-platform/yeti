import json
import logging
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class RequestLoggingTest(unittest.TestCase):
    """What the log_requests middleware puts in an audit record's body."""

    def setUp(self) -> None:
        # Other test modules disable logging and leave it disabled.
        previous = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        apikey = user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    def _logged_body(self, path: str, **request) -> str:
        """Posts a request and returns the body of its audit record."""
        with self.assertLogs("yeti.audit.log", level="INFO") as logs:
            client.post(path, **request)
        (record,) = [record for record in logs.records if record.path == path]
        return record.body

    def test_uploaded_file_is_logged_by_name_and_size(self) -> None:
        content = b"198.51.100.8\nuploaded.example.com\n"

        body = self._logged_body(
            "/api/v2/observables/import/file",
            files={"file": ("iocs.txt", content, "text/plain")},
            data={"tags": "tag1"},
        )

        self.assertEqual(
            json.loads(body),
            {"tags": "tag1", "file": f"<file 'iocs.txt', {len(content)} bytes>"},
        )

    def test_form_without_a_file_is_logged_as_json(self) -> None:
        body = self._logged_body(
            "/api/v2/auth/token",
            files={"username": (None, "test"), "password": (None, "hunter2")},
        )

        self.assertEqual(json.loads(body), {"username": "test", "password": "hunter2"})

    def test_multipart_body_that_cannot_be_parsed_is_not_logged(self) -> None:
        body = self._logged_body(
            "/api/v2/observables/import/file",
            content=b"--other\r\nnot a form: 198.51.100.8\r\n",
            headers={"content-type": "multipart/form-data; boundary=expected"},
        )

        self.assertNotIn("198.51.100.8", str(body))

    def test_json_body_is_logged_unchanged(self) -> None:
        request = {"value": "198.51.100.9", "type": "ipv4", "tags": []}

        body = self._logged_body("/api/v2/observables/", json=request)

        self.assertEqual(json.loads(body), request)
