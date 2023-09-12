import logging
import pandas as pd
from io import StringIO
from datetime import timedelta
from core.schemas.observables import ipv4, url
from core.schemas import task
from core import taskmanager


class ViriBackTracker(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "ViriBackTracker",
        "description": "Malware C2 Urls and IPs",
    }
    SOURCE = "http://tracker.viriback.com/dump.php"
    

    def run(self):
        response = self._make_request(self.SOURCE)
        if response:
            data = response.text
            df = pd.read_csv(
                StringIO(data),
                parse_dates=["FirstSeen"],
            )
            df.fillna("", inplace=True)
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
        tags = ['c2']
        if family:
            tags.append(family)

        if url_str:
            url_obs = url.Url.find(value=url_str)
            if not url_obs:
                url_obs = url.Url(value=url_str).save()
            url_obs.add_context(self.name, context)
            url_obs.tag(tags)

        if ip_str:
            ip_obs = ipv4.IPv4.find(value=ip_str)
            if not ip_obs:
                ip_obs = ipv4.IPv4(value=ip_str).save() 

            ip_obs.add_context(self.name, context)
            ip_obs.tag(tags)
        if url_obs and ip_obs:
            url_obs.link_to(ip_obs, "resolve_to", self.name)
        
taskmanager.TaskManager.register_task(ViriBackTracker)