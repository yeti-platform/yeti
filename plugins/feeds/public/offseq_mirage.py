from datetime import timedelta
from io import StringIO
from typing import ClassVar

import pandas as pd

from core import taskmanager
from core.schemas import task
from core.schemas.observables import ipv4, url


class OffSeqMirage(task.FeedTask):
    _SOURCE: ClassVar["str"] = (
        "https://feeds.offseq.com/mirage-feed/latest/attackers-ipv4-7d.csv"
    )
    _URLS: ClassVar["str"] = "https://feeds.offseq.com/mirage-feed/latest/urls-7d.txt"
    # VPN and Tor exits are listed for context only, never in the feed's block lists
    _ANONYMIZERS: ClassVar[set[str]] = {"vpn-exit", "tor-exit"}
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "OffSeqMirage",
        "description": "OffSeq Mirage Feed: handshake-verified attacker IPs and payload URLs seen by a honeypot fleet (daily, CC BY 4.0, no API key needed)",
    }

    def run(self):
        response = self._make_request(self._SOURCE, sort=False)
        if response:
            df = pd.read_csv(StringIO(response.text), dtype=str, keep_default_na=False)
            df["last_seen"] = pd.to_datetime(df["last_seen"]).dt.tz_localize(None)
            df = self._filter_observables_by_time(df, "last_seen")
            for _, line in df.iterrows():
                self.analyze(line)

        response = self._make_request(self._URLS, sort=False)
        if response:
            for line in response.text.splitlines():
                self.analyze_url(line)

    def analyze(self, item):
        feed_tags = [tag for tag in item["tags"].split(";") if tag]
        if self._ANONYMIZERS.intersection(feed_tags):
            return

        context = {
            "asn": item["asn"],
            "as_org": item["as_org"],
            "country": item["country"],
            "first_seen": item["first_seen"],
            "last_seen": str(item["last_seen"]),
            "services": item["services"],
            "cves": item["cves"],
            "attack": item["attack"],
            "confidence": item["confidence"],
        }

        ip_obs = ipv4.IPv4(value=item["ip"]).save()
        ip_obs.add_context(self.name, context)
        ip_obs.tag(["offseq-mirage", "attacker"] + feed_tags)

    def analyze_url(self, url_str):
        url_str = url_str.strip()
        if not url_str or url_str.startswith("#"):
            return
        url_obs = url.Url(value=url_str).save()
        url_obs.add_context(self.name, {"source": self.name})
        url_obs.tag(["offseq-mirage", "payload"])


taskmanager.TaskManager.register_task(OffSeqMirage)
