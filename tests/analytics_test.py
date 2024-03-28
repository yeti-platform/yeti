import datetime
import os
import unittest
from unittest.mock import MagicMock, patch

from censys.search import CensysHosts
from parameterized import parameterized

from core import database_arango
from core.config.config import yeti_config
from core.schemas import indicator, observable
from core.schemas.indicator import DiamondModel
from core.schemas.observable import ObservableType
from plugins.analytics.public import censys, expire_tags, shodan
from tests.helpers import YetiTestCase


class CensysAnalyticsTest(YetiTestCase):
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
            query_type="censys",
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
            "192.0.2.1",
            "2001:db8:3333:4444:5555:6666:7777:8888",
        ]

        self.check_neighbors(censys_query, expected_neighbor_values)


class ShodanAnalyticsTest(YetiTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    @parameterized.expand([(-1, 5), (500, 5), (3, 3), (None, 5)])
    @patch("plugins.analytics.public.shodan.Shodan")
    def test_shodan_query_with_various_limits(self, limit, expected_count, mock_shodan):
        mock_shodan_api = MagicMock()
        mock_shodan.return_value = mock_shodan_api

        os.environ["YETI_SHODAN_API_KEY"] = "test_api_key"

        indicator.Query(
            name="Shodan test query name",
            description="Shodan test query description",
            pattern="shodan_test_query",
            location="shodan",
            diamond=DiamondModel.infrastructure,
            relevant_tags=["shodan_query_tag"],
            query_type="shodan",
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
            query_type="shodan",
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
