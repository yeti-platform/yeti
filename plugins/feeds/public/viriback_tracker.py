import logging
import pandas as pd
from io import StringIO
from datetime import timedelta, datetime
from core.schemas import observable
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
        response = self._make_request(self.SOURCE, verify=True)
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
        url = line["URL"]
        ip = line["IP"]
        first_seen = line["FirstSeen"]
        family = family.lower()
        context = {
            "first_seen": first_seen,
            "source": self.name,
            "date_added": datetime.utcnow(),
        }

        if url:
            url_obs  = observable.Observable.find(value=url)
            if not url_obs:
                url_obs = observable.Observable(value=url, type="url")
            url_obs.add_context(self.name, context)
            url_obs.tag(['c2', family])

        if ip:
            obs_ip = observable.Observable.find(value=ip)
            if not obs_ip:
                obs_ip = observable.Observable(value=ip, type="ip")
            obs_ip.add_context(self.name, context)
            obs_ip.tag(['c2', family])

        if url_obs and ip_obs:
            url_obs.link_to(ip_obs, "resolve_to", self.name)

taskmanager.TaskManager.register_task(ViriBackTracker)