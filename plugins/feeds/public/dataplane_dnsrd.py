from datetime import timedelta
from typing import ClassVar

import pandas as pd

from core import taskmanager
from core.schemas import task
from core.schemas.observables import asn, ipv4


class DataplaneDNSRecursive(task.FeedTask):
    """
    Feed of Dataplane DNS Recursive IPs with ASN
    """

    _SOURCE: ClassVar["str"] = "https://dataplane.org/dnsrd.txt"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "DataplaneDNSRecursive",
        "description": "Feed of Dataplane DNS Recursive IPs with ASN",
    }
    _NAMES = [
        "ASN",
        "ASname",
        "ipaddr",
        "lastseen",
        "category",
    ]

    def run(self):
        response = self._make_request(self._SOURCE, sort=False)
        if response:
            lines = response.content.decode("utf-8").split("\n")[64:-5]
            df = pd.DataFrame([line.split("|") for line in lines], columns=self._NAMES)
            df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
            df["lastseen"] = pd.to_datetime(df["lastseen"])
            df.ffill(inplace=True)
            df = self._filter_observables_by_time(df, "lastseen")
            for _, row in df.iterrows():
                self.analyze(row)

    def analyze(self, item):
        if not item["ipaddr"]:
            return

        context_ip = {
            "source": self.name,
            "last_seen": item["lastseen"],
        }

        ip_obs = ipv4.IPv4(value=item["ipaddr"]).save()
        category = item["category"].lower()
        tags = ["dataplane", "dnsrd"]
        if category:
            tags.append(category)
        ip_obs.add_context(self.name, context_ip)
        ip_obs.tag(tags)

        asn_obs = asn.ASN(value=item["ASN"]).save()
        context_asn = {
            "source": self.name,
            "name": item["ASname"],
            "last_seen": item["lastseen"],
        }
        asn_obs.add_context(self.name, context_asn)
        asn_obs.tag(tags)

        asn_obs.link_to(ip_obs, "ASN_IP", self.name)


taskmanager.TaskManager.register_task(DataplaneDNSRecursive)
