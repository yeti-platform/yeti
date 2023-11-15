"""
       Feed DataplaneProto41: IPs from DataplaneProto41
"""
import logging
from datetime import timedelta
from typing import ClassVar

import pandas as pd
from core.schemas.observables import ipv4, asn
from core.schemas import task
from core import taskmanager


class DataplaneProto41(task.FeedTask):
    """
    Feed DataplaneProto41: IPs from DataplaneProto41
    """

    _SOURCE: ClassVar["str"] = "https://dataplane.org/proto41.txt"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "DataplaneProto41",
        "description": "Feed DataplaneProto41: IPs from DataplaneProto41",
    }
    _NAME = ["ASN", "ASname", "ipaddr", "firstseen", "lastseen", "category"]

    def run(self):
        response = self._make_request(self._SOURCE, sort=False)
        if response:
            lines = response.content.decode("utf-8").split("\n")[64:-5]

            df = pd.DataFrame([l.split("|") for l in lines], columns=self._NAME)
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
            "firstseen": item["firstseen"],
            "lastseen": item["lastseen"],
        }
        
        ip_obs = ipv4.IPv4(value=item["ipaddr"]).save()
        category = item["category"].lower()
        tags = ["dataplane", "proto41"]
        if category:
            tags.append(category)
        ip_obs.add_context(self.name, context_ip)
        ip_obs.tag(tags)

        asn_obs = asn.ASN(value=item["ASN"]).save()
        context_asn = {
            "source": self.name,
            "name": item["ASname"],
            "firstseen": item["firstseen"],
            "lastseen": item["lastseen"],
        }
        asn_obs.add_context(self.name, context_asn)
        asn_obs.tag(tags)

        asn_obs.link_to(ip_obs, "ASN_IP", self.name)


taskmanager.TaskManager.register_task(DataplaneProto41)
