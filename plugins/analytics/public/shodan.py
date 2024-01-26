import logging
from typing import Optional
from datetime import timedelta

from core.schemas import task
from core import taskmanager
from core.config.config import yeti_config
from core.schemas.observable import Observable
from core.schemas import indicator
from shodan import Shodan


class ShodanApiQuery(task.AnalyticsTask):
    _defaults = {
        "name": "Shodan",
        "description": "Executes Shodan queries (stored as indicators) and tags the returned IP addresses.",
        "frequency": timedelta(hours=24),
    }

    def run(self):
        api_key = yeti_config.get("shodan", "api_key")
        result_limit = yeti_config.get("shodan", "result_limit", 100)

        if not api_key:
            logging.error("Error: please configure an api_key to use Shodan analytics")
            raise RuntimeError

        shodan_api = Shodan(api_key)

        shodan_queries, _ = indicator.Query.filter(
            {"query_type": indicator.QueryType.shodan}
        )

        for query in shodan_queries:
            ip_addresses = self.query_shodan(shodan_api, query.pattern, result_limit)
            for ip in ip_addresses:
                ip_object = Observable.add_text(ip)
                ip_object.tag(query.relevant_tags)
                query.link_to(
                    ip_object, "shodan", f"IP found with Shodan query: {query.pattern}"
                )

    def query_shodan(self, api: Shodan, query: str, limit: int) -> set[Optional[str]]:
        """Queries Shodan and returns a set of identified IP addresses."""
        ip_addresses: set[Optional[str]] = set()
        count = 0

        for record in api.search_cursor(query):
            ip_addresses.add(record.get("ip_str"))
            if limit != -1:
                count += 1
                if count >= limit:
                    break

        return ip_addresses


taskmanager.TaskManager.register_task(ShodanApiQuery)
