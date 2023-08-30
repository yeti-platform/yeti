"""Azorult Tracker feeds"""
from datetime import timedelta, datetime
import logging
import pandas as pd
import numpy as np
from core.schemas import observable
from core.schemas import task
from core import taskmanager


class AzorutTracker(task.FeedTask):
    """Azorult Tracker"""

    SOURCE = "https://azorult-tracker.net/api/last-data"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "Azorult-Tracker",
        "description": "This feed contains panels of Azorult",
    }

    def run(self):
        response = self._make_request(self.SOURCE, auth=None)
        if response:
            data = response.json()

            df = pd.DataFrame(data)
            df.replace({np.nan: None}, inplace=True)

            df["first_seen"] = pd.to_datetime(df["first_seen"], unit="s")
            if self.last_run:
                df = df[df["first_seen"] > self.last_run]

            for _, item in df.iterrows():
                self.analyze(item)

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
                hostname = observable.Observable.find(value=domain)
                if not hostname:
                    hostname = observable.Observable(
                        value=domain, type="hostname"
                    ).save()

                hostname.add_context(self.name, context)
                hostname.tag(["azorult"])
            if ip:
                ip_obs = observable.Observable.find(value=ip)
                if not ip_obs:
                    ip_obs = observable.Observable(value=ip, type="ip").save()
                ip_obs.add_context(self.name, context)
                ip_obs.tag(["azorult"])

            if panel_url:
                url = observable.Observable.find(value=panel_url)
                if not url:
                    url = observable.Observable(value=panel_url, type="url").save()
                url.add_context(self.name, context)
                url.tag(["azorult"])

            if asn:
                asn_obs = observable.Observable.find(value=asn)
                if not asn_obs:
                    asn_obs = observable.Observable(value=asn, type="asn").save()
                asn_obs.add_context(self.name, context)
                asn_obs.tag(["azorult"])

            if hostname and ip_obs:
                hostname.link_to(ip_obs, "hostname-ip", self.name)
            if asn_obs and ip_obs:
                asn_obs.link_to(ip_obs, "asn-ip", self.name)
            if url and hostname:
                url.link_to(hostname, "url-hostname", self.name)

        except Exception as e:
            logging.error(e)


taskmanager.TaskManager.register_task(AzorutTracker)
