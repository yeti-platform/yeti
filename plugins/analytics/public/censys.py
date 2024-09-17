import logging
from datetime import timedelta

from censys.search import CensysHosts

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import task
from core.schemas.indicators.query import Query
from core.schemas.observable import Observable


class CensysApiQuery(task.AnalyticsTask):
    _defaults = {
        "name": "Censys",
        "description": "Executes Censys queries (stored as indicators) and tags the returned IP addresses.",
        "frequency": timedelta(hours=24),
    }

    def run(self):
        api_key = yeti_config.get("censys", "api_key")
        api_secret = yeti_config.get("censys", "secret")

        if not (api_key and api_secret):
            logging.error(
                "Error: please configure an api_key and secret to use Censys analytics"
            )
            raise RuntimeError

        hosts_api = CensysHosts(
            api_id=api_key,
            api_secret=api_secret,
        )

        censys_queries, _ = Query.filter({"query_type": "censys"})

        for query in censys_queries:
            ip_addresses = query_censys(hosts_api, query.pattern)
            for ip in ip_addresses:
                ip_object = Observable.add_text(ip)
                ip_object.tag(query.relevant_tags)
                query.link_to(
                    ip_object, "censys", f"IP found with Censys query: {query.pattern}"
                )


def query_censys(api: CensysHosts, query: str) -> set[str]:
    """Queries Censys and returns all identified IP addresses."""
    ip_addresses: set[str] = set()
    results = api.search(query, fields=["ip"], pages=-1)

    for result in results:
        for record in result:
            ip = record.get("ip")
            if ip is not None:
                ip_addresses.add(ip)

    return ip_addresses


taskmanager.TaskManager.register_task(CensysApiQuery)
