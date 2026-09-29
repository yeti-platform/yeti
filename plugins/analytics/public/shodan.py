import logging
from datetime import timedelta

from shodan import APIError, Shodan

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import indicator, observable, task


class ShodanApiQuery(task.AnalyticsTask):
    _defaults = {
        "name": "Shodan",
        "description": "Executes Shodan queries (stored as indicators) and tags the returned IP addresses.",
        "frequency": timedelta(hours=24),
    }

    def run(self):
        api_key = yeti_config.get("shodan", "api_key")
        result_limit = yeti_config.get("shodan", "result_limit")
        if not result_limit:
            result_limit = 100
        else:
            result_limit = int(result_limit)

        if not api_key:
            logging.error("Error: please configure an api_key to use Shodan analytics")
            raise RuntimeError

        shodan_api = Shodan(api_key)

        # "~" matches as a case-insensitive regex; anchoring makes it exact.
        shodan_queries, _ = indicator.Query.filter({"query_type~": "^shodan$"})

        failures = []
        for query in shodan_queries:
            # One failing query (bad syntax, no credits left) must not stop
            # the others; the run still fails afterwards so it gets noticed.
            try:
                ip_addresses = query_shodan(shodan_api, query.pattern, result_limit)
            except APIError as error:
                logging.error(f"Shodan query {query.name} failed: {error}")
                failures.append(f"{query.name}: {error}")
                continue
            for ip in ip_addresses:
                ip_object = observable.save(value=ip)
                ip_object.tag(query.relevant_tags)
                query.link_to(
                    ip_object, "shodan", f"IP found with Shodan query: {query.pattern}"
                )

        if failures:
            raise RuntimeError(
                f"{len(failures)} of {len(shodan_queries)} Shodan queries failed: "
                + "; ".join(failures)
            )


def query_shodan(api: Shodan, query: str, limit: int) -> set[str]:
    """Queries Shodan and returns a set of identified IP addresses."""
    ip_addresses: set[str] = set()
    count = 0

    for record in api.search_cursor(query):
        if record.get("ip_str") is not None:
            ip_addresses.add(record.get("ip_str"))
            # Setting the limit to -1 indicates the user wants unlimited results.
            if limit != -1:
                count += 1
                if count >= limit:
                    break

    return ip_addresses


taskmanager.TaskManager.register_task(ShodanApiQuery)
