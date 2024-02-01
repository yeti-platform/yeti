import datetime
import os
import unittest

from core.config.config import yeti_config
from unittest.mock import patch, MagicMock
from censys.search import CensysHosts

from typing import Any
from core import database_arango
from core.schemas import indicator, observable
from core.schemas.indicator import DiamondModel
from core.schemas.observable import ObservableType
from core.schemas import observable
from parameterized import parameterized
from plugins.analytics.public import censys, expire_tags, shodan
from core.schemas import indicator


class AnalyticsTestBase(unittest.TestCase):

    def check_observables(self, expected_values: list[dict[str, Any]]):
        """Checks observables against a list of expected values.

        Args:
            expected_values: A list of dictionaries, each containing expected values
                for 'value', 'type', and 'tags' attributes.
        """
        observables = observable.Observable.filter(
            {"value": ""}, graph_queries=[("tags", "tagged", "outbound", "name")]
        )
        observable_obj, _ = observables

        self.assertEqual(len(observable_obj), len(expected_values))

        for obs, expected_value in zip(observable_obj, expected_values):
            self.assertEqual(obs.value, expected_value["value"])
            self.assertEqual(obs.type, expected_value["type"])
            self.assertEqual(set(obs.tags.keys()), expected_value["tags"])

    def check_neighbors(self, indicator: indicator.Query, expected_neighbor_values: list[str]):
        """Checks an indicator's neighbors against a list of expected values.

        Args:
            indicator: The indicator.Query object to use for neighbor comparison.
            expected_neighbor_values: A list of expected neighbor values.
        """
        indicator_neighbors = [
            o.value
            for o in indicator.neighbors()[0].values()
            if isinstance(o, observable.Observable)
        ]

        for expected_value in expected_neighbor_values:
            self.assertIn(expected_value, indicator_neighbors)


class CensysAnalyticsTest(AnalyticsTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    @patch("plugins.analytics.public.censys.CensysHosts")
    def test_censys_query(self, mock_censys_hosts):
        mock_hosts_api = MagicMock(spec=CensysHosts)
        mock_censys_hosts.return_value = mock_hosts_api

        os.environ["YETI_CENSYS_API_KEY"] = "test_api_key"
        os.environ["YETI_CENSYS_SECRET"] = "test_secret"

        censys_query = indicator.Query(
            name="Censys test query name",
            description="Censys test query description",
            pattern="test_censys_query",
            location="censys",
            diamond=DiamondModel.infrastructure,
            relevant_tags=["censys_query_tag"],
            query_type=indicator.QueryType.censys,
        ).save()

        mock_search_result = [
            {"ip": "192.0.2.1"},
            {"ip": "2001:db8:3333:4444:5555:6666:7777:8888"},
        ]
        mock_hosts_api.search.return_value = [mock_search_result]

        defaults = censys.CensysApiQuery._defaults.copy()
        analytics = censys.CensysApiQuery(**defaults)

        analytics.run()

        mock_censys_hosts.assert_called_once()
        mock_hosts_api.search.assert_called_once_with(
            "test_censys_query", fields=["ip"], pages=-1
        )

        expected_observable_values = [
            {
                "value": "192.0.2.1",
                "type": ObservableType.ipv4,
                "tags": {"censys_query_tag"},
            },
            {
                "value": "2001:db8:3333:4444:5555:6666:7777:8888",
                "type": ObservableType.ipv6,
                "tags": {"censys_query_tag"},
            },
        ]

        self.check_observables(expected_observable_values)

        expected_neighbor_values = [
            "192.0.2.1", "2001:db8:3333:4444:5555:6666:7777:8888"
        ]

        self.check_neighbors(censys_query, expected_neighbor_values)



class ShodanAnalyticsTest(AnalyticsTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    @parameterized.expand([(-1, 5), (500, 5), (3, 3)])
    @patch("plugins.analytics.public.shodan.Shodan")
    def test_shodan_query_with_various_limits(self, limit, expected_count, mock_shodan):
        mock_shodan_api = MagicMock()
        mock_shodan.return_value = mock_shodan_api

        os.environ["YETI_SHODAN_API_KEY"] = "test_api_key"

        shodan_query = indicator.Query(
            name="Shodan test query name",
            description="Shodan test query description",
            pattern="shodan_test_query",
            location="shodan",
            diamond=DiamondModel.infrastructure,
            relevant_tags=["shodan_query_tag"],
            query_type=indicator.QueryType.shodan,
        ).save()

        def mock_search_cursor(query):
            records = [
                {"ip_str": "192.0.2.1"},
                {"ip_str": "192.0.2.2"},
                {"ip_str": "192.0.2.3"},
                {"ip_str": "192.0.2.4"},
                {"ip_str": "192.0.2.5"},
            ]

            return iter(records)

        mock_shodan_api.search_cursor.side_effect = mock_search_cursor

        defaults = shodan.ShodanApiQuery._defaults.copy()
        analytics = shodan.ShodanApiQuery(**defaults)

        with patch.object(yeti_config.shodan, "result_limit", limit):
            analytics.run()

            mock_shodan_api.search_cursor.assert_called_with("shodan_test_query")

            observables = observable.Observable.filter(
                {"value": ""}, graph_queries=[("tags", "tagged", "outbound", "name")]
            )
            observable_obj, _ = observables

            observables_added = [o.value for o in observable_obj]
            self.assertEqual(len(observables_added), expected_count)

    @patch("plugins.analytics.public.shodan.Shodan")
    def test_shodan_observables_and_neighbors(self, mock_shodan):
        mock_shodan_api = MagicMock()
        mock_shodan.return_value = mock_shodan_api

        os.environ["YETI_SHODAN_API_KEY"] = "test_api_key"

        shodan_query = indicator.Query(
            name="Shodan test query name",
            description="Shodan test query description",
            pattern="shodan_test_query",
            location="shodan",
            diamond=DiamondModel.infrastructure,
            relevant_tags=["shodan_query_tag"],
            query_type=indicator.QueryType.shodan,
        ).save()

        def mock_search_cursor(query):
            records = [
                {"ip_str": "192.0.2.1"},
                {"ip_str": "192.0.2.2"},
                {"ip_str": "192.0.2.3"},
                {"ip_str": "192.0.2.4"},
                {"ip_str": "192.0.2.5"},
            ]
            return iter(records)

        mock_shodan_api.search_cursor.side_effect = mock_search_cursor

        analytics = shodan.ShodanApiQuery(**shodan.ShodanApiQuery._defaults.copy())
        analytics.run()

        expected_observable_values = [
            {
                "value": "192.0.2.1",
                "type": ObservableType.ipv4,
                "tags": {"shodan_query_tag"},
            },
            {
                "value": "192.0.2.2",
                "type": ObservableType.ipv4,
                "tags": {"shodan_query_tag"},
            },
            {
                "value": "192.0.2.3",
                "type": ObservableType.ipv4,
                "tags": {"shodan_query_tag"},
            },
            {
                "value": "192.0.2.4",
                "type": ObservableType.ipv4,
                "tags": {"shodan_query_tag"},
            },
            {
                "value": "192.0.2.5",
                "type": ObservableType.ipv4,
                "tags": {"shodan_query_tag"},
            },
        ]

        self.check_observables(expected_observable_values)

        expected_neighbor_values = [
            "192.0.2.1",
            "192.0.2.2",
            "192.0.2.3",
            "192.0.2.4",
            "192.0.2.5",
        ]

        self.check_neighbors(shodan_query, expected_neighbor_values)

    def test_expire_tags(self) -> None:
        o = observable.Observable.add_text("google.com")
        o.tag(["test_tag"], expiration=datetime.timedelta(seconds=-10))

        defaults = expire_tags.ExpireTags._defaults.copy()
        analytics = expire_tags.ExpireTags(**defaults)

        self.assertTrue(o.tags["test_tag"].fresh)
        analytics.run()
        o.get_tags()
        self.assertFalse(o.tags["test_tag"].fresh)


if __name__ == "__main__":
    unittest.main()
