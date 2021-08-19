"""Azorult Tracker feeds"""
from datetime import timedelta,datetime
import logging
import pandas as pd
import numpy as np
from core.feed import Feed
from core.observables import AutonomousSystem, Ip, Hostname, Url
from core.errors import ObservableValidationError


class AzorutTracker(Feed):
    """Azorult Tracker"""

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "Azorult-Tracker",
        "source": "https://azorult-tracker.net/api/last-data",
        "description": "This feed contains panels of Azorult",
    }

    def update(self):
        for index, item in self.update_json():
            self.analyze(item)

    def update_json(self):

        r = self._make_request()

        if r.status_code == 200:
            res = r.json()

            df = pd.DataFrame(res)
            df.replace({np.nan: None}, inplace=True)

            df["first_seen"] = pd.to_datetime(df["first_seen"], unit="s")
            if self.last_run:
                df = df[df["first_seen"] > self.last_run]
            return df.iterrows()

    def analyze(self, item):
        context = {"source": self.name, "date_added": datetime.utcnow()}

        _id = item["_id"]
        domain = item["domain"]
        ip = item["ip"]
        asn = item["asn"]
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
            hostname = None
            url = None
            ip_obs = None
            asn_obs = None

            if domain:
                hostname = Hostname.get_or_create(value=domain)
                hostname.add_context(context, dedup_list=["date_added"])
                hostname.tag("azorult")
            if ip:
                ip_obs = Ip.get_or_create(value=ip)
                ip_obs.add_context(context, dedup_list=["date_added"])
                ip_obs.tag("azorult")
            if panel_url:
                url = Url.get_or_create(value=panel_url)
                url.add_context(context, dedup_list=["date_added"])
                url.tag("azorult")

            if asn:
                asn_obs = AutonomousSystem.get_or_create(value=asn)
                asn_obs.add_context(context, dedup_list=["date_added"])
                asn_obs.tag("azorult")

            if hostname and ip_obs:
                hostname.active_link_to(ip_obs, "IP", self.name)
            if asn_obs and ip_obs:
                asn_obs.active_link_to(ip_obs, "AS", self.name)
            if url and hostname:
                url.active_link_to(hostname, "hostname", self.name)

        except ObservableValidationError as e:
            logging.error(e)
        except TypeError as e:
            logging.error(item)
