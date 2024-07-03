from datetime import timedelta
from io import StringIO
from typing import ClassVar

import pandas as pd
from core import taskmanager
from core.schemas import task
from core.schemas.observables import ipv4, url


class ViriBackTracker(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "ViriBackTracker",
        "description": "Malware C2 Urls and IPs",
    }

    _SOURCE: ClassVar["str"] = "http://tracker.viriback.com/dump.php"

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            df = pd.read_csv(
                StringIO(data),
                parse_dates=["FirstSeen"],
                date_format="%d-%m-%Y"
            )
            df.ffill(inplace=True)
            df = self._filter_observables_by_time(df, "FirstSeen")
            for _, line in df.iterrows():
                self.analyze(line)

    def analyze(self, line):
        url_obs = False
        ip_obs = False
        family = line["Family"]
        url_str = line["URL"]
        ip_str = line["IP"]
        first_seen = line["FirstSeen"]
        family = family.lower()
        context = {
            "first_seen": first_seen,
            "source": self.name,
        }
        tags = ["c2"]
        if family:
            tags.append(family)

        if url_str:
            url_obs = url.Url(value=url_str).save()
            url_obs.add_context(self.name, context)
            url_obs.tag(tags)

        if ip_str:
            ip_obs = ipv4.IPv4(value=ip_str).save()
            ip_obs.add_context(self.name, context)
            ip_obs.tag(tags)

        if url_obs and ip_obs:
            url_obs.link_to(ip_obs, "resolve_to", self.name)


taskmanager.TaskManager.register_task(ViriBackTracker)
