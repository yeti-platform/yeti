"""
       Feed of Dataplane SSH bruteforce IPs and ASNs
"""
import logging
from datetime import datetime, timedelta

import pandas as pd
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import AutonomousSystem, Ip


class DataplaneSSHPwAuth(Feed):
    """
    Feed of Dataplane SSH bruteforce IPs and ASNs
    """

    default_values = {
        "frequency": timedelta(hours=2),
        "name": "DataplaneSSHPwAuth",
        "source": "https://dataplane.org/sshpwauth.txt",
        "description": "Entries below are records of source IP addresses that have been identified as attempting login via SSH password authentication.",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[68:-5]
        columns = ["ASN", "ASname", "ipaddr", "lastseen", "category"]
        df = pd.DataFrame([l.split("|") for l in lines], columns=columns)

        for c in columns:
            df[c] = df[c].str.strip()
        df = df.dropna()
        df["lastseen"] = pd.to_datetime(df["lastseen"])
        if self.last_run:
            df = df[df["lastseen"] > self.last_run]
        for count, row in df.iterrows():
            self.analyze(row)

    def analyze(self, item):

        context_ip = {
            "source": self.name,
            "last_seen": item["lastseen"],
            "date_added": datetime.utcnow(),
        }

        try:
            ip = Ip.get_or_create(value=item["ipaddr"])
            ip.add_context(context_ip, dedup_list=["date_added"])
            ip.add_source(self.name)
            ip.tag("dataplane")
            ip.tag("ssh")
            ip.tag("bruteforce")
            ip.tag(item["category"])

            asn = AutonomousSystem.get_or_create(value=item["ASN"])
            context_ans = {"source": self.name, "name": item["ASname"]}
            asn.add_context(context_ans, dedup_list=["date_added"])
            asn.add_source(self.name)
            asn.tag("dataplane")
            asn.active_link_to(ip, "AS", self.name)
        except ObservableValidationError as e:
            logging.error(e)
