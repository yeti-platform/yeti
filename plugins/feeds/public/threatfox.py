import logging
from datetime import timedelta
from core import Feed
import pandas as pd
from core.observables import Ip, Observable
from core.errors import ObservableValidationError


class ThreatFox(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "ThreatFox",
        "source": "https://threatfox.abuse.ch/export/json/recent/",
        "description": "Feed ThreatFox by Abuse.ch",
    }

    def update(self):
        for index, line in self.update_json():
            self.analyze(line)

    def update_json(self):
        r = self._make_request(sort=False)

        if r:
            res = r.json()

            values = [r[0] for r in res.values()]

            df = pd.DataFrame(values)

            df["first_seen_utc"] = pd.to_datetime(df["first_seen_utc"])
            df["last_seen_utc"] = pd.to_datetime(df["last_seen_utc"])
            if self.last_run:
                df = df[df["first_seen_utc"] > self.last_run]
            df.fillna("-", inplace=True)
            return df.iterrows()

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
        try:
            if "ip" in ioc_type:
                value, port = ioc_value.split(":")
                context["port"] = port
                obs = Ip.get_or_create(value=value)
            else:
                obs = Observable.add_text(ioc_value)

        except ObservableValidationError as e:
            logging.error(e)
            return

        if obs:
            obs.add_context(context)
            obs.add_source(self.name)
            if tags:
                obs.tag(tags)
            if malware_printable:
                obs.tags
