import logging
from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import task
from core.schemas.observables import hostname


class NetAPITopDomains(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "NetAPITopDomains",
        "description": "Import NetAPI Top 1M domains (daily, CC BY 4.0, no API key needed)",
    }
    _SOURCE: ClassVar["str"] = "https://netapi.com/netapi_top1mln.csv"

    def run(self):
        top_domains = yeti_config.get("netapi", "top_domains", 10000)
        logging.info(f"Importing {top_domains} NetAPI top domains")
        response = self._make_request(self._SOURCE, sort=False)
        if not response:
            return
        context = {
            "name": self.name,
        }
        # the file is "NetAPI_Rank,Domain" sorted by rank: read only the first
        # top_domains rows instead of downloading all 1M
        lines = response.iter_lines(decode_unicode=True)
        next(lines, None)
        for line in lines:
            if top_domains <= 0:
                break
            line = line.strip()
            if not line:
                continue
            _, domain = line.split(",")
            hostname_obs = hostname.Hostname(value=domain).save()
            hostname_obs.add_context(self.name, context)
            hostname_obs.tag(["netapi", "top_domain"])
            top_domains -= 1
        response.close()


taskmanager.TaskManager.register_task(NetAPITopDomains)
