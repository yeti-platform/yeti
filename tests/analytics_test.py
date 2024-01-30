import datetime
import os
import unittest
from unittest.mock import MagicMock, patch

from censys.search import CensysHosts

from core import database_arango
from core.schemas import indicator, observable
from core.schemas.indicator import DiamondModel
from core.schemas.observable import ObservableType
from plugins.analytics.public import censys, expire_tags


class AnalyticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.connect(database="yeti_test")
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

        observables = observable.Observable.filter(
            {"value": ""}, graph_queries=[("tags", "tagged", "outbound", "name")]
        )
        observable_obj, _ = observables

        self.assertEqual(observable_obj[0].value, "192.0.2.1")
        self.assertEqual(observable_obj[0].type, ObservableType.ipv4)
        self.assertEqual(set(observable_obj[0].tags.keys()), {"censys_query_tag"})

        self.assertEqual(
            observable_obj[1].value, "2001:db8:3333:4444:5555:6666:7777:8888"
        )
        self.assertEqual(observable_obj[1].type, ObservableType.ipv6)
        self.assertEqual(set(observable_obj[1].tags.keys()), {"censys_query_tag"})

        query_neighbors = [o.value for o in censys_query.neighbors()[0].values()]
        self.assertIn("192.0.2.1", query_neighbors)
        self.assertIn("2001:db8:3333:4444:5555:6666:7777:8888", query_neighbors)

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
