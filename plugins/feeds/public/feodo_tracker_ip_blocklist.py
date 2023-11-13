import datetime
from io import StringIO
from typing import ClassVar

import pandas as pd

from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class FeodoTrackerIPBlockList(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    _defaults = {
        "frequency": datetime.timedelta(hours=24),
        "name": "FeodoTrackerIPBlocklist",
        "source": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description": "Feodo Tracker IP Feed. This feed shows a full list C2s.",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            df = pd.read_csv(
                StringIO(data),
                comment="#",
                delimiter=",",
                quotechar='"',
                quoting=True,
                skipinitialspace=True,
                parse_dates=["first_seen_utc"],
            )
            df = self._filter_observables_by_time(df, "first_seen_utc")
            df.fillna("", inplace=True)
            for _, line in df.iterrows():
                self.analyze(line)

    def analyze(self, item):
        tags = ["c2", "blocklist"]
        tags.append(item["malware"].lower())

        context = {
            "first_seen": str(item["first_seen_utc"]),
            "last_online": item["last_online"],
            "c2_status": item["c2_status"],
            "port": item["dst_port"],
        }

        ip_observable = ipv4.IPv4(value=item["dst_ip"]).save()
        ip_observable.add_context(source=self.name, context=context)
        ip_observable.tag(tags)


taskmanager.TaskManager.register_task(FeodoTrackerIPBlockList)
