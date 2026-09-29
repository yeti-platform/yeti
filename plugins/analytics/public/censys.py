import logging
import math
from datetime import timedelta

import requests
from censys.common.exceptions import CensysException
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

        # "~" matches as a case-insensitive regex; anchoring makes it exact.
        censys_queries, _ = indicator.Query.filter({"query_type~": "^censys$"})

        failures = []
        for query in censys_queries:
            # One failing query (bad syntax, rate limit) must not stop the
            # others; the run still fails afterwards so it gets noticed. The
            # Censys client lets network errors through as requests errors.
            try:
                ip_addresses = query_censys(hosts_api, query.pattern, max_results)
            except (CensysException, requests.RequestException) as error:
                logging.error(f"Censys query {query.name} failed: {error}")
                failures.append(f"{query.name}: {error}")
                continue
            for ip in ip_addresses:
                ip_object = observable.save(value=ip)
                ip_object.tag(query.relevant_tags)
                query.link_to(
                    ip_object, "censys", f"IP found with Censys query: {query.pattern}"
                )

        if failures:
            raise RuntimeError(
                f"{len(failures)} of {len(censys_queries)} Censys queries failed: "
                + "; ".join(failures)
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
