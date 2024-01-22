import unittest
from unittest.mock import patch, MagicMock
from plugins.analytics.public import censys
from core import database_arango
from censys.search import CensysHosts
from core.schemas import indicator, observable

class AnalyticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    @patch('plugins.analytics.public.censys.CensysHosts')
    @patch('plugins.analytics.public.censys.indicator.Query.filter')
    @patch('plugins.analytics.public.censys.Observable.add_text')
    def test_censys_query(self, mock_add_text, mock_filter, mock_censys_hosts):
        mock_hosts_api = MagicMock(spec=CensysHosts)
        mock_censys_hosts.return_value = mock_hosts_api

        mock_query = MagicMock(spec=indicator.Query)
        mock_query.pattern = 'test_pattern'
        mock_query.relevant_tags = ['test_tag']
        mock_query.link_to = MagicMock()
        mock_filter.return_value = ([mock_query], 1)

        mock_search_result = [{'ip': '192.0.2.1'}, {'ip': '203.0.113.2'}]
        mock_hosts_api.search.return_value = [mock_search_result]

        mock_observable_instance = MagicMock(spec=observable.Observable)
        mock_observable_instance.tag = MagicMock()
        mock_add_text.return_value = mock_observable_instance

        defaults = censys.CensysApiQuery._defaults.copy()
        analytics = censys.CensysApiQuery(**defaults)
        analytics.run()

        mock_censys_hosts.assert_called_once()
        mock_filter.assert_called_once_with({'query_type': indicator.QueryType.censys})
        mock_hosts_api.search.assert_called_once_with('test_pattern', fields=['ip'], pages=-1)
        mock_observable_instance.tag.assert_called_with(['test_tag'])
        mock_query.link_to.assert_called_with(mock_observable_instance, 'censys','IP found with Censys query: test_pattern')

if __name__ == '__main__':
    unittest.main()
