import io
from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import task
from core.schemas.observables import hostname


class CiscoUmbrellaTopDomains(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "CloudflareTopDomains",
        "description": "Import Cloudflare top domains",
    }
    _SOURCE: ClassVar[
        "str"
    ] = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"

    def run(self):
        top_domains = yeti_config.get("umbrella", "top_domains", 10000)
        response = self._make_request(self._SOURCE, sort=False)
        data = self._unzip_content(response.content)
        context = {
            "name": self.name,
        }
        feed = io.BytesIO(data)
        while top_domains > 0:
            line = feed.readline().decode("utf-8").strip()
            _, domain = line.split(",")
            hostname_obs = hostname.Hostname(value=domain).save()
            hostname_obs.add_context(self.name, context)
            hostname_obs.tag(["cisco_umbrella", "top_domain"])
            top_domains -= 1


taskmanager.TaskManager.register_task(CiscoUmbrellaTopDomains)
