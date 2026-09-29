import json
import os
import time
import unittest
from unittest import mock

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


class ShodanQueryTest(unittest.TestCase):
    """Which Shodan queries a run sends."""

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


class CensysQueryTest(unittest.TestCase):
    """Which Censys queries a run sends."""

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
