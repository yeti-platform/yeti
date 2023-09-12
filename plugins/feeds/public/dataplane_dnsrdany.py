import logging
from datetime import timedelta
import numpy as np
import pandas as pd
from core.schemas.observables import ipv4,asn
from core.schemas import task
from core import taskmanager


class DataplaneDNSAny(task.FeedTask):
    """
    Feed of dataplane dns any Ips with ASN
    """

    SOURCE = "https://dataplane.org/dnsrdany.txt"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "DataplaneDNSAny",
        "description": "Feed of dataplane dns any Ips with ASN",
    }
    _NAMES = ["ASN", "ASname", "ipaddr", "lastseen", "category"]
    def run(self):
        response = self._make_request(self.SOURCE,sort=False)
        if response:
            lines = response.content.decode("utf-8").split("\n")[64:-5]
           
            df = pd.DataFrame([l.split("|") for l in lines], columns=self._NAMES)
            df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
            df = df.dropna()
            df["lastseen"] = pd.to_datetime(df["lastseen"])
            df.fillna("", inplace=True)

            df = self._filter_observables_by_time(df, "lastseen")

            for _, row in df.iterrows():
                self.analyze(row)

    def analyze(self, item):
        context_ip = {
            "source": self.name,
            "last_seen": item["lastseen"],
        }

        ip_obs = ipv4.IPv4.find(value=item["ipaddr"])
        if not ip_obs:
            ip_obs = ipv4.IPv4(value=item["ipaddr"]).save()
        category = item["category"].lower()
        tags = ["dataplane", "dnsany"]
        if category:
            tags.append(category)
        ip_obs.add_context(self.name, context_ip)
        ip_obs.tag(tags)

        asn_obs = asn.ASN.find(value=item["ASN"])
        if not asn_obs:
            asn_obs = asn.ASN(value=item["ASN"]).save()
        context_asn = {
            "source": self.name,
            "name": item["ASname"],
            "last_seen": item["lastseen"],
        }
        asn_obs.add_context(self.name, context_asn)
        asn_obs.tag(["dataplane", "dnsany"])
        asn_obs.tag(tags)

        asn_obs.link_to(ip_obs, "ASN_IP", self.name)


taskmanager.TaskManager.register_task(DataplaneDNSAny)
