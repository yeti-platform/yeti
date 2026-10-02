import json
import os
import time
import unittest
from unittest import mock

import requests
from censys.common.exceptions import CensysRateLimitExceededException
from shodan import APIError

from core import database_arango
from core.schemas import indicator, observable
from core.schemas.indicator import DiamondModel
from plugins.analytics.public import censys, github, shodan


def save_queries(queries: dict[str, str], pattern=lambda name: name) -> None:
    for name, query_type in queries.items():
        indicator.Query(
            name=name,
            pattern=pattern(name),
            query_type=query_type,
            diamond=DiamondModel.infrastructure,
            relevant_tags=["c2"],
        ).save()
    # The analytics find their queries through indicators_view, which indexes
    # new documents asynchronously.
    for _ in range(50):
        if indicator.Query.filter({"name": ""})[1] >= len(queries):
            return
        time.sleep(0.1)
    raise AssertionError(f"indicators_view never showed {len(queries)} queries")


def failing(error: Exception):
    """An iterator that raises when first read, like a client's result cursor."""
    raise error
    yield  # makes this a generator


class ShodanQueryTest(unittest.TestCase):
    """Which Shodan queries a run sends, and what a failing one does to the run."""

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        env = mock.patch.dict(os.environ, {"YETI_SHODAN_API_KEY": "test"})
        env.start()
        self.addCleanup(env.stop)
        client = mock.patch("plugins.analytics.public.shodan.Shodan", autospec=True)
        self.api = client.start().return_value
        self.addCleanup(client.stop)
        self.api.search_cursor.side_effect = self.search_cursor
        self.analytics = shodan.ShodanApiQuery(**shodan.ShodanApiQuery._defaults.copy())

    def search_cursor(self, query: str):
        if query.startswith("broken"):
            return failing(APIError("Insufficient query credits"))
        return iter([{"ip_str": "192.0.2.1", "port": 443, "transport": "tcp"}])

    def sent(self) -> list[str]:
        return sorted(call.args[0] for call in self.api.search_cursor.call_args_list)

    def test_query_type_match_ignores_case(self) -> None:
        """A query typed "Shodan" or "SHODAN" is a Shodan query too."""
        save_queries({"lower": "shodan", "capitalized": "Shodan", "upper": "SHODAN"})

        self.analytics.run()

        self.assertEqual(self.sent(), ["capitalized", "lower", "upper"])

    def test_only_exact_query_type_runs(self) -> None:
        """Types that merely contain "shodan" belong to something else."""
        save_queries(
            {"exact": "shodan", "suffixed": "shodan-c2", "prefixed": "not-shodan"}
        )

        self.analytics.run()

        self.assertEqual(self.sent(), ["exact"])

    def test_near_miss_query_types_are_logged(self) -> None:
        """A query typed "shodan-c2" is not run, but a warning names it so the
        operator can correct the query type."""
        save_queries(
            {"wanted": "shodan", "suffixed": "shodan-c2", "prefixed": "not-shodan"}
        )

        with self.assertLogs(level="WARNING") as logs:
            self.analytics.run()

        self.assertEqual(self.sent(), ["wanted"])
        messages = "\n".join(record.getMessage() for record in logs.records)
        for name in ("suffixed", "shodan-c2", "prefixed", "not-shodan"):
            self.assertIn(name, messages)
        self.assertNotIn("wanted", messages)

    def test_failing_query_does_not_stop_the_others(self) -> None:
        """Every query is sent, working ones keep their results, and each
        failure is reported.

        Two failing queries make this independent of the order the view
        returns them in: at least one of them is followed by another query.
        """
        save_queries({"broken-1": "shodan", "broken-2": "shodan", "working": "shodan"})

        with self.assertRaises(Exception) as raised:
            self.analytics.run()

        self.assertEqual(self.sent(), ["broken-1", "broken-2", "working"])
        for failed in ("broken-1", "broken-2"):
            self.assertIn(failed, str(raised.exception))
        ip = observable.Observable.find(value="192.0.2.1")
        self.assertIsNotNone(ip)
        self.assertEqual({tag.name for tag in ip.tags}, {"c2"})

    def test_failed_queries_are_reported(self) -> None:
        """The run still fails, naming each failed query and its error."""
        save_queries({"broken-1": "shodan", "working": "shodan"})

        with self.assertRaises(Exception) as raised:
            self.analytics.run()

        message = str(raised.exception)
        self.assertIn("broken-1", message)
        self.assertIn("Insufficient query credits", message)
        self.assertNotIn("working", message)


class CensysQueryTest(unittest.TestCase):
    """Which Censys queries a run sends, and what a failing one does to the run."""

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        env = mock.patch.dict(
            os.environ,
            {"YETI_CENSYS_API_KEY": "test", "YETI_CENSYS_SECRET": "test"},
        )
        env.start()
        self.addCleanup(env.stop)
        client = mock.patch(
            "plugins.analytics.public.censys.CensysHosts", autospec=True
        )
        self.api = client.start().return_value
        self.addCleanup(client.stop)
        self.api.search.side_effect = self.search
        self.analytics = censys.CensysApiQuery(**censys.CensysApiQuery._defaults.copy())

    def search(self, query: str, **kwargs):
        if query == "broken-api":
            return failing(CensysRateLimitExceededException(429, "Rate limit exceeded"))
        if query == "broken-network":
            return failing(requests.ConnectionError("Connection refused"))
        return iter([[{"ip": "192.0.2.1"}]])

    def sent(self) -> list[str]:
        return sorted(call.args[0] for call in self.api.search.call_args_list)

    def test_query_type_match_ignores_case(self) -> None:
        """A query typed "Censys" or "CENSYS" is a Censys query too."""
        save_queries({"lower": "censys", "capitalized": "Censys", "upper": "CENSYS"})

        self.analytics.run()

        self.assertEqual(self.sent(), ["capitalized", "lower", "upper"])

    def test_only_exact_query_type_runs(self) -> None:
        """Types that merely contain "censys" belong to something else."""
        save_queries(
            {"exact": "censys", "suffixed": "censys-c2", "prefixed": "not-censys"}
        )

        self.analytics.run()

        self.assertEqual(self.sent(), ["exact"])

    def test_failing_query_does_not_stop_the_others(self) -> None:
        """API and network errors both leave the other queries running, and
        both are reported.

        Naming both failures catches a dropped except clause for either error
        type, whatever order the view returns the queries in.
        """
        save_queries(
            {"broken-api": "censys", "broken-network": "censys", "working": "censys"}
        )

        with self.assertRaises(Exception) as raised:
            self.analytics.run()

        self.assertEqual(self.sent(), ["broken-api", "broken-network", "working"])
        for failed in ("broken-api", "broken-network"):
            self.assertIn(failed, str(raised.exception))
        ip = observable.Observable.find(value="192.0.2.1")
        self.assertIsNotNone(ip)
        self.assertEqual({tag.name for tag in ip.tags}, {"c2"})

    def test_failed_queries_are_reported(self) -> None:
        """The run still fails, naming each failed query and its error."""
        save_queries({"broken-api": "censys", "working": "censys"})

        with self.assertRaises(Exception) as raised:
            self.analytics.run()

        message = str(raised.exception)
        self.assertIn("broken-api", message)
        self.assertIn("Rate limit exceeded", message)
        self.assertNotIn("working", message)


class GithubQueryTest(unittest.TestCase):
    """Which GitHub queries a run sends."""

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        env = mock.patch.dict(os.environ, {"YETI_GITHUB_TOKEN": "test"})
        env.start()
        self.addCleanup(env.stop)
        client = mock.patch("plugins.analytics.public.github.Github", autospec=True)
        self.api = client.start().return_value
        self.addCleanup(client.stop)
        self.api.search_repositories.return_value = []
        self.analytics = github.GithubMonitor(**github.GithubMonitor._defaults.copy())

    def sent(self) -> list[str]:
        calls = self.api.search_repositories.call_args_list
        return sorted(call.args[0] for call in calls)

    @staticmethod
    def repositories_search(name: str) -> str:
        return json.dumps([{"type": "repositories", "query": name}])

    def test_query_type_match_ignores_case(self) -> None:
        """A query typed "GitHub" or "GITHUB" is a GitHub query too."""
        save_queries(
            {"lower": "github", "capitalized": "GitHub", "upper": "GITHUB"},
            pattern=self.repositories_search,
        )

        self.analytics.run()

        self.assertEqual(self.sent(), ["capitalized", "lower", "upper"])

    def test_only_exact_query_type_runs(self) -> None:
        """Types that merely contain "github" belong to something else."""
        save_queries(
            {"exact": "github", "suffixed": "github-c2", "prefixed": "not-github"},
            pattern=self.repositories_search,
        )

        self.analytics.run()

        self.assertEqual(self.sent(), ["exact"])
