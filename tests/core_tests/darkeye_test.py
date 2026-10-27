"""Synthetic API responses; no live credentials or real leak data."""

import importlib
import unittest
from unittest.mock import Mock, patch

import requests

from core import taskmanager

with patch.object(taskmanager.TaskManager, "register_task"):
    darkeye = importlib.import_module("plugins.analytics.public.darkeye")

HIBR_URL = "https://haveibeenransom.com/api/metadata/domain/example.com"
BREACH_HOUSE_URL = "https://breach.house/api/v1/search"


def leak(id_source, post_title, group_name, leak_type, website=""):
    return {
        "id_source": id_source,
        "post_title": post_title,
        "group_name": group_name,
        "leak_type": leak_type,
        "website": website,
        "discovered": "2025-03-04 10:11:12.123456",
    }


def response(data, status_code=200):
    mock = Mock(status_code=status_code)
    mock.json.return_value = data
    return mock


HIBR_PAGES = {
    HIBR_URL: {
        "sources": [
            leak("101", "Example Corp", "akira", "ransomware_leak", "example.com"),
            leak("db-7", "example.com customers", "𝐃𝐁𝐬  𝐁𝐚𝐜𝐤𝐮𝐩", "traditional_breach"),
        ],
        "page": 1,
        "has_next": True,
    },
    # Leaks without metadata are left out, so a page can be empty and still
    # have a next page.
    f"{HIBR_URL}/2": {"sources": [], "page": 2, "has_next": True},
    # A leak indexed while paging is repeated on a later page.
    f"{HIBR_URL}/3": {
        "sources": [
            leak("101", "Example Corp", "akira", "ransomware_leak"),
            leak("102", "", "play", "ransomware_leak", "shop.example.com"),
        ],
        "page": 3,
        "has_next": False,
    },
}

BREACH_HOUSE_SEARCH = {
    "ransomware": [
        {
            "id": 12345,
            "victim_id": "AbCdEf123456",
            "post_title": "Example Corp",
            "group_name": "akira",
            "country": "US",
            "website": "example.com",
            "discovered": "2025-03-04 10:11:12.123456",
            "leak_status": "leaked",
            "download_link": "http://example.onion/files",
            "meta_description": "Leak-site text",
        }
    ],
    "breaches": [],
    "leads": [],
    "stealers": [{"id": 321, "website": "shop.example.com", "country": "ES"}],
}


def fake_get(url, **kwargs):
    if url == BREACH_HOUSE_URL:
        return response(BREACH_HOUSE_SEARCH)
    return response(HIBR_PAGES[url])


def hibr(record_id, category, title, website, group):
    return {
        "product": "Have I Been Ransomed?",
        "category": category,
        "id": record_id,
        "title": title,
        "website": website,
        "group": group,
        "country": "",
        "discovered": "2025-03-04",
    }


HIBR_RECORDS = [
    hibr("101", "ransomware", "Example Corp", "example.com", "akira"),
    hibr("db-7", "breaches", "example.com customers", "", "DBs Backup"),
    hibr("102", "ransomware", "shop.example.com", "shop.example.com", "play"),
]

BREACH_HOUSE_RECORDS = [
    {
        "product": "Breach House",
        "category": "ransomware",
        "id": "AbCdEf123456",
        "title": "Example Corp",
        "website": "example.com",
        "group": "akira",
        "country": "US",
        "discovered": "2025-03-04",
    },
    {
        "product": "Breach House",
        "category": "stealers",
        "id": "321",
        "title": "shop.example.com",
        "website": "shop.example.com",
        "group": "",
        "country": "ES",
        "discovered": "",
    },
]


class DarkEyeTest(unittest.TestCase):
    def setUp(self):
        self.settings: dict = {
            "haveibeenransom_api_key": "synthetic-hibr-key",
            "breachhouse_api_key": "synthetic-bh-key",
        }
        self.config = patch.object(darkeye.yeti_config, "get")
        get_config = self.config.start()
        get_config.side_effect = lambda section, key=None, default=None: (
            self.settings.get(key) if section == "darkeye" else {}
        )
        self.addCleanup(self.config.stop)

    @patch.object(darkeye.requests, "get")
    def test_both_products_are_queried_and_merged(self, get):
        get.side_effect = fake_get
        records, products, truncated, errors = darkeye.fetch_records("Example.com.")
        self.assertFalse(truncated)
        self.assertEqual(errors, [])
        self.assertEqual(products, ["Have I Been Ransomed?", "Breach House"])
        self.assertEqual(records, HIBR_RECORDS + BREACH_HOUSE_RECORDS)
        self.assertNotIn("example.onion", str(records))
        self.assertNotIn("Leak-site text", str(records))
        urls = [call.args[0] for call in get.call_args_list]
        self.assertEqual(
            urls, [HIBR_URL, f"{HIBR_URL}/2", f"{HIBR_URL}/3", BREACH_HOUSE_URL]
        )
        hibr_call, *_, breach_house_call = get.call_args_list
        self.assertEqual(
            hibr_call.kwargs["headers"]["Authorization"], "Bearer synthetic-hibr-key"
        )
        self.assertEqual(
            breach_house_call.kwargs["headers"]["Authorization"],
            "Bearer synthetic-bh-key",
        )
        self.assertEqual(
            breach_house_call.kwargs["params"], {"q": "example.com", "limit": 25}
        )
        for call in get.call_args_list:
            self.assertFalse(call.kwargs["allow_redirects"])
            self.assertEqual(call.kwargs["timeout"], 30)

    @patch.object(darkeye.requests, "get")
    def test_only_products_with_a_key_are_queried(self, get):
        get.side_effect = fake_get
        self.settings["breachhouse_api_key"] = ""
        records, products, *_ = darkeye.fetch_records("example.com")
        self.assertEqual(products, ["Have I Been Ransomed?"])
        self.assertEqual(records, HIBR_RECORDS)

        get.reset_mock()
        self.settings["haveibeenransom_api_key"] = ""
        self.settings["breachhouse_api_key"] = "synthetic-bh-key"
        records, products, *_ = darkeye.fetch_records("example.com")
        self.assertEqual(products, ["Breach House"])
        self.assertEqual(records, BREACH_HOUSE_RECORDS)
        self.assertEqual(get.call_count, 1)

    @patch.object(darkeye.requests, "get")
    def test_documented_hibr_response_shape(self, get):
        self.settings["breachhouse_api_key"] = ""
        get.return_value = response(
            {
                "success": True,
                "results": [leak("201", "Example Corp", "lockbit3", "ransomware_leak")],
                "pagination": {"current_page": 1, "total_pages": 1, "has_next": False},
            }
        )
        records, _, truncated, _ = darkeye.fetch_records("example.com")
        self.assertFalse(truncated)
        self.assertEqual([record["group"] for record in records], ["lockbit3"])

    @patch.object(darkeye.requests, "get")
    def test_page_and_result_limits_report_truncation(self, get):
        get.side_effect = fake_get
        self.settings["max_pages"] = 1
        self.settings["breachhouse_api_key"] = ""
        records, _, truncated, _ = darkeye.fetch_records("example.com")
        self.assertTrue(truncated)
        self.assertEqual(get.call_count, 1)
        self.assertEqual(len(records), 2)

        self.settings["haveibeenransom_api_key"] = ""
        self.settings["breachhouse_api_key"] = "synthetic-bh-key"
        self.settings["limit"] = 1
        _, _, truncated, _ = darkeye.fetch_records("example.com")
        self.assertTrue(truncated)
        self.assertEqual(get.call_args.kwargs["params"]["limit"], 1)
        self.settings["limit"] = 1000
        darkeye.fetch_records("example.com")
        self.assertEqual(get.call_args.kwargs["params"]["limit"], 200)

    @patch.object(darkeye.Observable, "save")
    @patch.object(darkeye, "fetch_records")
    def test_repeated_lookup_replaces_the_previous_context(self, fetch_records, save):
        first = HIBR_RECORDS[:1]
        latest = HIBR_RECORDS + BREACH_HOUSE_RECORDS
        products = ["Have I Been Ransomed?", "Breach House"]
        fetch_records.side_effect = [
            (first, products, False, []),
            (latest, products, False, []),
        ]
        other_context = {"source": "Investigation", "note": "Keep this context"}
        observable = darkeye.Observable(value="example.com", context=[other_context])
        action = darkeye.DarkEyeLookup(**darkeye.DarkEyeLookup._defaults)

        action.each(observable)
        action.each(observable)

        contexts = [
            context for context in observable.context if context["source"] == "DarkEye"
        ]
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["record_count"], 5)
        self.assertEqual(contexts[0]["records"], latest)
        self.assertEqual(contexts[0]["products"], products)
        self.assertEqual(observable.context[0], other_context)
        self.assertEqual(save.call_count, 2)

    @patch.object(darkeye.requests, "get")
    def test_http_errors_do_not_add_context(self, get):
        observable = Mock(value="example.com")
        action = darkeye.DarkEyeLookup(**darkeye.DarkEyeLookup._defaults)
        for status in (302, 400, 401, 403, 429, 500):
            with self.subTest(status=status):
                get.side_effect = None
                get.return_value = response({"error": "x"}, status_code=status)
                with self.assertRaises(RuntimeError):
                    action.each(observable)
                observable.add_context.assert_not_called()

    @patch.object(darkeye.requests, "get")
    def test_one_failing_product_keeps_the_other_records(self, get):
        def breach_house_down(url, **kwargs):
            if url == BREACH_HOUSE_URL:
                return response({"error": "x"}, status_code=500)
            return response(HIBR_PAGES[url])

        get.side_effect = breach_house_down
        records, products, truncated, errors = darkeye.fetch_records("example.com")
        self.assertEqual(records, HIBR_RECORDS)
        self.assertEqual(products, ["Have I Been Ransomed?"])
        self.assertFalse(truncated)
        self.assertEqual(errors, ["Breach House returned HTTP 500."])

        def hibr_down(url, **kwargs):
            if url == BREACH_HOUSE_URL:
                return response(BREACH_HOUSE_SEARCH)
            raise requests.Timeout("Bearer synthetic-hibr-key")

        get.side_effect = hibr_down
        records, products, _, errors = darkeye.fetch_records("example.com")
        self.assertEqual(records, BREACH_HOUSE_RECORDS)
        self.assertEqual(products, ["Breach House"])
        self.assertEqual(errors, ["Have I Been Ransomed? request failed or timed out."])
        self.assertNotIn("synthetic-hibr-key", str(errors))

    @patch.object(darkeye.Observable, "save")
    @patch.object(darkeye.requests, "get")
    def test_partial_failure_is_reported_in_the_context(self, get, save):
        def hibr_down(url, **kwargs):
            if url == BREACH_HOUSE_URL:
                return response(BREACH_HOUSE_SEARCH)
            return response({"error": "x"}, status_code=429)

        get.side_effect = hibr_down
        observable = darkeye.Observable(value="example.com", context=[])
        action = darkeye.DarkEyeLookup(**darkeye.DarkEyeLookup._defaults)
        action.each(observable)
        (context,) = observable.context
        self.assertEqual(context["products"], ["Breach House"])
        self.assertEqual(context["record_count"], len(BREACH_HOUSE_RECORDS))
        self.assertEqual(
            context["errors"],
            ["Have I Been Ransomed? quota or rate limit reached; retry later."],
        )

    @patch.object(darkeye.requests, "get")
    def test_all_products_failing_fails_the_lookup(self, get):
        get.return_value = response({"error": "x"}, status_code=500)
        with self.assertRaisesRegex(
            RuntimeError,
            "Have I Been Ransomed\\? returned HTTP 500. Breach House returned HTTP 500.",
        ):
            darkeye.fetch_records("example.com")

    @patch.object(darkeye.requests, "get")
    def test_timeout_is_an_explicit_failure(self, get):
        get.side_effect = requests.Timeout("Bearer synthetic-hibr-key")
        with self.assertRaisesRegex(RuntimeError, "failed or timed out") as caught:
            darkeye.fetch_records("example.com")
        self.assertNotIn("synthetic-hibr-key", str(caught.exception))

    @patch.object(darkeye.requests, "get")
    def test_invalid_response_fails(self, get):
        get.return_value = response([])
        with self.assertRaisesRegex(RuntimeError, "invalid response"):
            darkeye.fetch_records("example.com")
        get.return_value.json.side_effect = ValueError("invalid JSON")
        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            darkeye.fetch_records("example.com")

    @patch.object(darkeye.requests, "get")
    def test_missing_keys_and_non_domains_make_no_request(self, get):
        for value in ("*.example.com", "exam?le.com", "example", "  "):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    darkeye.fetch_records(value)
        self.settings["haveibeenransom_api_key"] = ""
        self.settings["breachhouse_api_key"] = ""
        with self.assertRaisesRegex(RuntimeError, "Configure"):
            darkeye.fetch_records("example.com")
        get.assert_not_called()
