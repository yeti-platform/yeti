"""Synthetic API responses; no live credentials or customer indicators."""

import importlib
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from core import taskmanager

with patch.object(taskmanager.TaskManager, "register_task"):
    ismalicious = importlib.import_module("plugins.analytics.public.ismalicious")


class IsMaliciousTest(unittest.TestCase):
    def setUp(self):
        self.config = patch.object(ismalicious.yeti_config, "get")
        self.get_config = self.config.start()
        self.get_config.side_effect = lambda section, key=None: (
            "synthetic-encoded-credential" if section == "ismalicious" else {}
        )
        self.addCleanup(self.config.stop)

    @patch.object(ismalicious.requests, "get")
    def test_unknown_hash_is_preserved_without_tags(self, get):
        report = json.loads(
            (
                Path(__file__).parent / "ismalicious_data" / "unknown-hash.json"
            ).read_text()
        )
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = report
        observable = Mock(value="0" * 64)
        action = ismalicious.IsMaliciousReport(
            **ismalicious.IsMaliciousReport._defaults
        )
        action.each(observable)
        key, context = observable.add_context.call_args.args
        self.assertEqual(key, "IsMalicious")
        self.assertEqual(context["report"], report)
        self.assertEqual(context["report"]["evidence"]["verdict"], "unknown")
        observable.tag.assert_not_called()

    @patch.object(ismalicious.requests, "get")
    def test_url_is_sent_as_a_query_parameter(self, get):
        indicator = "https://example.invalid/path?a=one&b=two#fragment"
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"malicious": False, "sources": []}
        ismalicious.fetch_report(indicator)
        self.assertEqual(get.call_args.kwargs["params"]["query"], indicator)
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertEqual(get.call_args.kwargs["timeout"], 30)
        self.assertNotIn("synthetic-encoded-credential", get.call_args.args[0])

    @patch.object(ismalicious.requests, "get")
    def test_partial_context_response_is_preserved(self, get):
        report = {
            "malicious": False,
            "sources": [{"name": "context", "positive": False}],
        }
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = report
        self.assertEqual(ismalicious.fetch_report("example.invalid"), report)

    @patch.object(ismalicious.requests, "get")
    def test_http_errors_do_not_replace_context(self, get):
        observable = Mock(value="192.0.2.1")
        action = ismalicious.IsMaliciousReport(
            **ismalicious.IsMaliciousReport._defaults
        )
        for status in (302, 401, 403, 429, 500):
            with self.subTest(status=status):
                get.return_value = Mock(status_code=status)
                with self.assertRaises(RuntimeError):
                    action.each(observable)
                observable.add_context.assert_not_called()

    @patch.object(ismalicious.requests, "get")
    def test_timeout_is_an_explicit_failure(self, get):
        get.side_effect = requests.Timeout("sensitive request details")
        with self.assertRaisesRegex(RuntimeError, "failed or timed out") as caught:
            ismalicious.fetch_report("192.0.2.1")
        self.assertNotIn("sensitive", str(caught.exception))

    @patch.object(ismalicious.requests, "get")
    def test_invalid_response_fails(self, get):
        get.return_value = Mock(status_code=200)
        for report in ([], None, {"error": "failure"}):
            get.return_value.json.return_value = report
            with self.assertRaisesRegex(RuntimeError, "invalid report"):
                ismalicious.fetch_report("example.invalid")
        get.return_value.json.side_effect = ValueError("invalid JSON")
        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            ismalicious.fetch_report("example.invalid")

    @patch.object(ismalicious.requests, "get")
    def test_missing_credential_and_empty_indicator_make_no_request(self, get):
        self.get_config.return_value = None
        self.get_config.side_effect = None
        with self.assertRaisesRegex(RuntimeError, "Configure"):
            ismalicious.fetch_report("example.invalid")
        self.get_config.return_value = "synthetic-encoded-credential"
        with self.assertRaises(ValueError):
            ismalicious.fetch_report("  ")
        get.assert_not_called()
