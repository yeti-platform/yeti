import json
import logging
import unittest
import urllib.parse

from core.logger import JsonFormatter, LogFilter, text_log_format


def _audit_record(path: str, body: bytes | str, content_type: str):
    return logging.makeLogRecord(
        {
            "type": "audit.log",
            "path": path,
            "method": "POST",
            "body": body,
            "content-type": content_type,
        }
    )


def _request_record(body: str):
    """An audit record with every field the log_requests middleware sets."""
    return logging.makeLogRecord(
        {
            "name": "yeti.audit.log",
            "levelname": "INFO",
            "msg": "Authorized request",
            "type": "audit.log",
            "username": "alice",
            "path": "/api/v2/observables/",
            "method": "POST",
            "body": body,
            "content-type": "application/json",
            "client": "198.51.100.1",
            "status_code": 200,
        }
    )


class LogFilterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.log_filter = LogFilter()

    def test_redacts_tokens_in_json_bodies(self) -> None:
        for path, field in (
            ("/api/v2/auth/oidc-callback-token", "id_token"),
            ("/api/v2/auth/google-access-token", "access_token"),
        ):
            with self.subTest(path=path):
                record = _audit_record(
                    path, json.dumps({field: "sensitive-value"}), "application/json"
                )

                self.assertTrue(self.log_filter.filter(record))

                self.assertEqual(json.loads(record.body), {field: "REDACTED"})

    def test_redacts_passwords_and_keeps_other_json_fields(self) -> None:
        record = _audit_record(
            "/api/v2/users/",
            json.dumps({"username": "alice", "password": "hunter2", "admin": False}),
            "application/json",
        )

        self.log_filter.filter(record)

        self.assertEqual(
            json.loads(record.body),
            {"username": "alice", "password": "REDACTED", "admin": False},
        )

    def test_redacts_urlencoded_login_form(self) -> None:
        record = _audit_record(
            "/api/v2/auth/token",
            b"grant_type=password&username=alice&password=hunter2&client_secret=s3cr3t",
            "application/x-www-form-urlencoded",
        )

        self.log_filter.filter(record)

        self.assertEqual(
            urllib.parse.parse_qs(record.body),
            {
                "grant_type": ["password"],
                "username": ["alice"],
                "password": ["REDACTED"],
                "client_secret": ["REDACTED"],
            },
        )

    def test_drops_bodies_that_cannot_be_parsed(self) -> None:
        for body, content_type in (
            (b"hunter2", "text/plain"),
            (b"hunter2", "application/x-www-form-urlencoded"),
            (b"username=alice&hunter2", "application/x-www-form-urlencoded"),
            (b'["hunter2"]', "application/json"),
            (b"\xffhunter2", "application/json"),
        ):
            with self.subTest(body=body, content_type=content_type):
                record = _audit_record("/api/v2/auth/token", body, content_type)

                self.log_filter.filter(record)

                self.assertEqual(record.body, "REDACTED")

    def test_repeated_filtering_keeps_redaction(self) -> None:
        # Each audit log handler has its own filter, and they all process the
        # same record.
        for body, content_type in (
            (json.dumps({"access_token": "sensitive-value"}), "application/json"),
            (b"username=alice&password=hunter2", "application/x-www-form-urlencoded"),
            (b"hunter2", "text/plain"),
        ):
            with self.subTest(content_type=content_type):
                record = _audit_record("/api/v2/auth/token", body, content_type)
                self.log_filter.filter(record)
                redacted = record.body

                LogFilter().filter(record)

                self.assertEqual(record.body, redacted)

    def test_leaves_other_endpoints_untouched(self) -> None:
        body = json.dumps({"value": "example.com", "token": "not-a-credential"})
        record = _audit_record("/api/v2/observables/", body, "application/json")

        self.log_filter.filter(record)

        self.assertEqual(record.body, body)


class AuditLogBodyTest(unittest.TestCase):
    """The console and file formatters can leave the request body out."""

    BODY = {"value": "hunter2", "type": "generic"}

    def setUp(self) -> None:
        self.record = _request_record(json.dumps(self.BODY))

    def test_json_line_has_the_body_by_default(self) -> None:
        line = json.loads(JsonFormatter().format(self.record))

        self.assertEqual(line["body"], self.BODY)

    def test_json_line_without_the_body_keeps_the_other_fields(self) -> None:
        line = json.loads(JsonFormatter(include_body=False).format(self.record))

        self.assertNotIn("body", line)
        self.assertEqual(
            {key: line[key] for key in ("username", "path", "method", "client")},
            {
                "username": "alice",
                "path": "/api/v2/observables/",
                "method": "POST",
                "client": "198.51.100.1",
            },
        )
        self.assertEqual(line["status_code"], 200)

    def test_text_line_has_the_body_by_default(self) -> None:
        line = logging.Formatter(text_log_format()).format(self.record)

        self.assertTrue(
            line.endswith(
                "yeti.audit.log - INFO - Authorized request - alice"
                " - /api/v2/observables/ - POST"
                f" - {json.dumps(self.BODY)} - 198.51.100.1 - 200"
            ),
            line,
        )

    def test_text_line_without_the_body_keeps_the_other_fields(self) -> None:
        line = logging.Formatter(text_log_format(include_body=False)).format(
            self.record
        )

        self.assertNotIn("hunter2", line)
        self.assertTrue(
            line.endswith(
                "yeti.audit.log - INFO - Authorized request - alice"
                " - /api/v2/observables/ - POST - 198.51.100.1 - 200"
            ),
            line,
        )
