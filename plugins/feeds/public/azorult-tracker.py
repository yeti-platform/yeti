"""Azorult Tracker feeds"""
from datetime import timedelta, datetime
import logging
import pandas as pd
import numpy as np
from core.schemas.observables import ipv4, hostname, url, asn
from core.schemas import task
from core import taskmanager
from typing import ClassVar


class AzorultTracker(task.FeedTask):
    """Azorult Tracker"""

    _SOURCE:ClassVar['str'] = "https://azorult-tracker.net/api/last-data"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "Azorult-Tracker",
        "description": "This feed contains panels of Azorult",
    }

    def run(self):
        response = self._make_request(self._SOURCE, auth=None)
        if response:
            data = response.json()

            df = pd.DataFrame(data)
            df.replace({np.nan: None}, inplace=True)

            df["first_seen"] = pd.to_datetime(df["first_seen"], unit="s", utc=True)
            if self.last_run:
                df = df[df["first_seen"] > self.last_run]

            for _, item in df.iterrows():
                self.analyze(item)

    def analyze(self, item):
        context = {"source": self.name, "date_added": datetime.utcnow()}

        _id = item["_id"]
        domain = item["domain"]
        ip_str = item["ip"]
        asn_str = item["asn"]
        country_code = item["country_code"]
        panel_url = item["panel_index"]
        panel_path = item["panel_path"]
        panel_version = item["panel_version"]
        status = item["status"]
        feeder = item["feeder"]
        first_seen = item["first_seen"]

        context["first_seen"] = first_seen
        if feeder:
            context["feeder"] = feeder

        context["status"] = status
        if item["data"]:
            context["data"] = item["data"]

        context["country"] = country_code
        context["_id"] = _id
        context["panel_version"] = panel_version
        context["panel_path"] = panel_path
        context["date_added"] = datetime.utcnow()

        try:
            hostname_obs = None
            url_obs = None
            ip_obs = None
            asn_obs = None

            if domain:
                hostname_obs = hostname.Hostname(value=domain).save()

                hostname_obs.add_context(self.name, context)
                hostname_obs.tag(["azorult"])
            if ip_str:
                ip_obs = ipv4.IPv4(value=ip_str).save()
                ip_obs.add_context(self.name, context)
                ip_obs.tag(["azorult"])

            if panel_url:
                url_obs = url.Url(value=panel_url).save()
                url_obs.add_context(self.name, context)
                url_obs.tag(["azorult"])

            if asn_str:
                asn_obs = asn.ASN(value=asn_str).save()
                asn_obs.add_context(self.name, context)
                asn_obs.tag(["azorult"])

            if hostname_obs and ip_obs:
                hostname_obs.link_to(ip_obs, "hostname-ip", self.name)
            if asn_obs and ip_obs:
                asn_obs.link_to(ip_obs, "asn-ip", self.name)
            if url_obs and hostname_obs:
                url_obs.link_to(hostname_obs, "url-hostname", self.name)

        except Exception as e:
            logging.error(e)


taskmanager.TaskManager.register_task(AzorultTracker)
