from io import StringIO
import logging
from datetime import timedelta
from typing import ClassVar

import pandas as pd

from core.schemas.observables import url, asn, md5
from core.schemas import task
from core import taskmanager


class FutexTracker(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://futex.re/tracker/TinyTracker.csv"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "FutexTracker",
        "description": "Futex Tracker",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            names = ["id", "firstseen", "url", "status", "hash", "country", "as"]
            df = pd.read_csv(StringIO(data), names=names, delimiter=";", header=0)
            df.ffill(inplace=True)

            df = self._filter_observables_by_time(df, "firstseen")

            for _, row in df.iterrows():
                self.analyze(row)

    # pylint: disable=arguments-differ
    def analyze(self, item):
        _id = item["id"]
        _firsteen = item["firstseen"]
        url_str = item["url"]
        _status = item["status"]

        md5_str = item["hash"]

        country = item["country"]
        asn_str = item["as"]

        tags = ["collected_by_honeypot"]
        context = {
            "source": self.name,
            "country": country,
            "status": _status,
            "first_seen": _firsteen,
        }

        url_obs = None
        md5_obs = None
        asn_obs = None

        if url_str:
            url_obs = url.Url(value=url_str).save()
            url_obs.add_context(self.name, context)
            url_obs.tag(tags)

        if md5_str:
            md5_obs = md5.MD5(value=md5_str).save()
            md5_obs.add_context(self.name, context)
            md5_obs.tag(tags)

        if asn_str:
            asn_obs = asn.ASN(value=asn_str).save()
            asn_obs.add_context(self.name, context)
            asn_obs.tag(tags)

        if url_obs and md5_obs:
            url_obs.link_to(md5_obs, "URL to MD5", self.name)

        if url_obs and asn_obs:
            url_obs.link_to(asn_obs, "URL to ASN", self.name)


taskmanager.TaskManager.register_task(FutexTracker)
