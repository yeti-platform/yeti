"""
    Feed of ssh client bruteforce of Dataplane with IPs and ASNs
"""
from datetime import timedelta
from typing import ClassVar

import pandas as pd

from core import taskmanager
from core.schemas import task
from core.schemas.observables import asn, ipv4


class DataplaneSSHClient(task.FeedTask):
    """
    Feed of ssh client bruteforce of Dataplane with IPs and ASNs.
    """

    _SOURCE: ClassVar["str"] = "https://dataplane.org/sshclient.txt"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "DataplaneSSHClient",
        "description": "Feed of ssh client bruteforce of Dataplane with IPs and ASNs",
    }
    _NAMES = ["ASN", "ASname", "ipaddr", "lastseen", "category"]

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
        }

        ip_obs = ipv4.IPv4(value=item["ipaddr"]).save()
        category = item["category"].lower()
        tags = ["dataplane", "bruteforce", "ssh", "scanning"]
        if category:
            tags.append(category)
        ip_obs.add_context(self.name, context_ip)
        ip_obs.tag(tags)

        asn_obs = asn.ASN(value=item["ASN"]).save()
        context_asn = {
            "source": self.name,
        }
        asn_obs.add_context(self.name, context_asn)
        asn_obs.tag(tags)
        asn_obs.link_to(ip_obs, "ASN_IP", self.name)


taskmanager.TaskManager.register_task(DataplaneSSHClient)
