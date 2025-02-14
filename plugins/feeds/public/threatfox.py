from datetime import timedelta
from typing import ClassVar

import pandas as pd

from core import taskmanager
from core.schemas import task
from core.schemas.observables import hostname, ipv4, url


class ThreatFox(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "ThreatFox",
        "description": "This feed contains malware hashes and network IOCs",
    }
    _SOURCE: ClassVar["str"] = "https://threatfox.abuse.ch/export/json/recent/"

    def run(self):
        r = self._make_request(self._SOURCE, sort=False)

        if r:
            data = r.json()

            values = [r[0] for r in data.values()]

            df = pd.DataFrame(values)

            df["first_seen_utc"] = pd.to_datetime(df["first_seen_utc"])
            df["last_seen_utc"] = pd.to_datetime(df["last_seen_utc"])

            df = self._filter_observables_by_time(df, "first_seen_utc")
            df["last_seen_utc"] = df["last_seen_utc"].replace(pd.NaT, False)
        for _, line in df.iterrows():
            self.analyze(line)

    def analyze(self, item):
        first_seen = item["first_seen_utc"]
        ioc_value = item["ioc_value"]
        ioc_type = item["ioc_type"]
        threat_type = item["threat_type"]
        malware_alias = item["malware_alias"]
        malware_printable = item["malware_printable"]
        last_seen_utc = item["last_seen_utc"]
        confidence_level = item["confidence_level"]
        reference = item["reference"]
        reporter = item["reporter"]
        tags = []

        context = {"source": self.name}
        context["first_seen"] = first_seen

        if reference:
            context["reference"] = reference
        else:
            context["reference"] = "Unknown"

        if reporter:
            context["reporter"] = reporter
        else:
            context["reporter"] = "Unknown"

        if threat_type:
            context["threat_type"] = threat_type

        if item["tags"]:
            tags.extend(item["tags"].split(","))

        if malware_printable:
            tags.append(malware_printable)

        if malware_alias:
            context["malware_alias"] = malware_alias

        if last_seen_utc:
            context["last_seen_utc"] = last_seen_utc

        if confidence_level:
            context["confidence_level"] = confidence_level

        value = None
        obs = None

        if ioc_type in ["url", "ip", "domain"]:
            if ioc_type == "ip":
                value, port = ioc_value.split(":")
                context["port"] = port
                obs = ipv4.IPv4(value=value).save()
            elif ioc_type == "domain":
                value = ioc_value
                obs = hostname.Hostname(value=value).save()
            else:
                value = ioc_value
                obs = url.Url(value=value).save()
            obs.add_context(self.name, context)
            if malware_alias:
                tags.extend(malware_alias.split(","))
            tags.append(malware_printable)
            obs.tag(tags)


taskmanager.TaskManager.register_task(ThreatFox)
