from datetime import timedelta

from core.schemas import task
from core import taskmanager
from core.config.config import yeti_config
from core.schemas.observable import Observable
from core.schemas import indicator
from censys.search import CensysHosts


class CensysApiQuery(task.AnalyticsTask):
  _defaults = {
      "name": "Censys",
      "description": "Executes Censys queries (stored as indicators) and tags the returned IP addresses.",
      "frequency": timedelta(hours=24),
  }

  def run(self):
    hosts_api = CensysHosts(
        api_id=yeti_config.get("censys", "api_key"),
        api_secret=yeti_config.get("censys", "secret")
        )
    censys_queries, _ = indicator.Query.filter({'query_type': indicator.QueryType.censys})

    for query in censys_queries:
        ip_addresses = self.query_censys(hosts_api, query.pattern)
        for ip in ip_addresses:
          ip_object = Observable.add_text(ip)
          ip_object.tag(query.relevant_tags)
          query.link_to(ip_object, 'censys', f'IP found with Censys query: {query}')


  def query_censys(self, api, query: str) -> set[str]:
    """Queries Censys and returns all identified IP addresses."""
    ip_addresses: set[str] = set()
    results = api.search(query, fields=['ip'], pages=-1)
    for result in results:
        ip_addresses.update(record.get('ip') for record in result)

    return ip_addresses


taskmanager.TaskManager.register_task(CensysApiQuery)
