import logging
import math
from datetime import timedelta

from censys.search import CensysHosts

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import indicator, observable, task


class CensysApiQuery(task.AnalyticsTask):
    _defaults = {
        "name": "Censys",
        "description": "Executes Censys queries (stored as indicators) and tags the returned IP addresses.",
        "frequency": timedelta(hours=24),
    }

    def run(self):
        api_key = yeti_config.get("censys", "api_key")
        api_secret = yeti_config.get("censys", "secret")
        max_results = yeti_config.get("censys", "max_results", 1000)

        if not (api_key and api_secret):
            logging.error(
                "Error: please configure an api_key and secret to use Censys analytics"
            )
            raise RuntimeError

        hosts_api = CensysHosts(
            api_id=api_key,
            api_secret=api_secret,
        )

        censys_queries, _ = indicator.Query.filter({"query_type": "censys"})

        for query in censys_queries:
            ip_addresses = query_censys(hosts_api, query.pattern, max_results)
            for ip in ip_addresses:
                ip_object = observable.save(value=ip)
                ip_object.tag(query.relevant_tags)
                query.link_to(
                    ip_object, "censys", f"IP found with Censys query: {query.pattern}"
                )


def query_censys(api: CensysHosts, query: str, max_results=1000) -> set[str]:
    """Queries Censys and returns all identified IP addresses."""
    ip_addresses: set[str] = set()
    if max_results <= 0:
        results = api.search(query, fields=["ip"], pages=-1)
    elif max_results < 100:
        results = api.search(query, fields=["ip"], per_page=max_results, pages=1)
    else:
        pages = math.ceil(max_results / 100)
        results = api.search(query, fields=["ip"], per_page=100, pages=pages)

    for result in results:
        for record in result:
            ip = record.get("ip")
            if ip is not None:
                ip_addresses.add(ip)

    return ip_addresses


taskmanager.TaskManager.register_task(CensysApiQuery)
