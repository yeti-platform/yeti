import logging
from datetime import datetime, timedelta

from dateutil import parser
import pandas as pd
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class RulezSKBruteforceBlocker(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "RulezSKBruteforceBlocker",
        "description": "This feed contains daily list of IPs from rules.sk",
    }

    SOURCE = "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"

    def run(self):
        r = self._make_request(self.SOURCE, headers={"User-Agent": "yeti-project"})
        if r:
            data = [
                l.split("\t") for l in r.text.split("\n") if not l.startswith("#") and l
            ]
            df = pd.DataFrame(data)
            df.drop([1, 3], axis=1, inplace=True)
            df.columns = ["ip", "last_report", "count", "id"]
            df["last_report"] = df["last_report"].str.replace("# ", "")
            df["last_report"] = df["last_report"].apply(lambda x: parser.parse(x))

            df = self._filter_observables_by_time(df, "last_report")
            for _, row in df.iterrows():
                self.analyze(row)

    def analyze(self, row):
        context = {}
        context["first_seen"] = row["last_report"]
        context["source"] = self.name
        context["count"] = row["count"]
        context["id"] = row["id"]

        ipobs = ipv4.IPv4.find(value=row["ip"])
        if not ipobs:
            ipobs = ipv4.IPv4(value=row["ip"]).save()
        
        ipobs.add_context(self.name, context)
        ipobs.tag(["bruteforceblocker", "blocklist", "rules.sk"])


taskmanager.TaskManager.register_task(RulezSKBruteforceBlocker)
