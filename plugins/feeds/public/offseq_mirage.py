from datetime import timedelta
from io import StringIO
from typing import ClassVar

import pandas as pd

from core import taskmanager
from core.schemas import observable, task


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
        response = self._make_request(self._SOURCE)
        if response:
            df = pd.read_csv(StringIO(response.text), dtype=str, keep_default_na=False)
            df["last_seen_ts"] = pd.to_datetime(df["last_seen"]).dt.tz_localize(None)
            df = self._filter_observables_by_time(df, "last_seen_ts")
            for _, line in df.iterrows():
                self.analyze(line)

        response = self._make_request(self._URLS)
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
            "last_seen": item["last_seen"],
            "services": item["services"],
            "cves": item["cves"],
            "attack": item["attack"],
            "confidence": item["confidence"],
        }

        try:
            ip_obs = observable.save(
                type="ipv4",
                value=item["ip"],
                tags=["offseq-mirage", "attacker"] + feed_tags,
            )
            ip_obs.add_context(self.name, context, overwrite=True)
        except ValueError:
            self.logger.exception(f"Failed to save IP: {item['ip']}")

    def analyze_url(self, url_str):
        url_str = url_str.strip()
        if not url_str or url_str.startswith("#"):
            return
        try:
            url_obs = observable.save(
                type="url", value=url_str, tags=["offseq-mirage", "payload"]
            )
            url_obs.add_context(self.name, {"source": self.name})
        except ValueError:
            self.logger.exception(f"Failed to save URL: {url_str}")


taskmanager.TaskManager.register_task(OffSeqMirage)
