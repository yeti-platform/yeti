import io
import logging
from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import task
from core.schemas.observables import hostname


class TrancoTopDomains(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "TrancoTopDomains",
        "description": "Import Tranco top domains",
    }
    _SOURCE: ClassVar["str"] = "https://tranco-list.eu"

    def run(self):
        top_domains = yeti_config.get("tranco", "top_domains", 10000)
        include_subdomains = yeti_config.get("tranco", "include_subdomains", False)
        if include_subdomains:
            endpoint = "https://tranco-list.eu/download/J9X3Y/1000000"
        else:
            endpoint = "https://tranco-list.eu/download/QG9J4/1000000"
        logging.info(
            f"Importing {top_domains} Tranco top domains (include subdomains: {include_subdomains})"
        )
        response = self._make_request(endpoint, sort=False)
        context = {
            "name": self.name,
        }
        feed = io.BytesIO(response.content)
        while top_domains > 0:
            line = feed.readline().decode("utf-8").strip()
            _, domain = line.split(",")
            hostname_obs = hostname.Hostname(value=domain).save()
            hostname_obs.add_context(self.name, context)
            hostname_obs.tag(["tranco", "top_domain"])
            top_domains -= 1


taskmanager.TaskManager.register_task(TrancoTopDomains)
