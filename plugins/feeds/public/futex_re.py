from io import StringIO
import logging
from datetime import timedelta, datetime

import pandas as pd

from core.schemas import observable
from core.schemas import task
from core import taskmanager


class FutexTracker(task.FeedTask):
    SOURCE = "https://futex.re/tracker/TinyTracker.csv"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "FutexTracker",
        "description": "Futex Tracker",
    }

    def run(self):
        response = self._make_request(self.SOURCE, verify=True)
        if response:
            data = response.text
            names = ["id", "firstseen", "url", "status", "hash", "country", "as"]
            df = pd.read_csv(StringIO(data), names=names, delimiter=";",header=0)
            df.fillna("", inplace=True)

            df = self._filter_observables_by_time(df, "firstseen")
            
            for _, row in df.iterrows():
                self.analyze(row)

    # pylint: disable=arguments-differ
    def analyze(self, item):
        _id = item["id"]
        _ = item["firstseen"]
        url = item["url"]
        _status = item["status"]

        _hash = item["hash"]

        country = item["country"]
        asn = item["as"]

        tags = ["collected_by_honeypot"]
        context = {
            "source": self.name,
            "country": country,
            "status": _status,
        }

        url_obs = None

        if url:
            url_obs = observable.Observable.find(value=url)
            if not url_obs:
                url_obs = observable.Observable(value=url, type="url").save()
            url_obs.add_context(self.name, context)
            url_obs.tag(tags)

        if _hash and len(_hash) > 16:
            hash_obs = observable.Observable.find(value=_hash)
            if not hash_obs:
                hash_obs = observable.Observable(value=_hash, type="md5").save()
            hash_obs.add_context(self.name, context)
            hash_obs.tag(tags)
            if url_obs:
                hash_obs.link_to(url_obs, "downloaded", self.name)
        
        if asn:
            asn_obs = observable.Observable.find(value=asn)
            if not asn_obs:
                asn_obs = observable.Observable(value=asn, type="asn").save()
            asn_obs.add_context(self.name, context)
            asn_obs.tag(tags)
            if url_obs:
                asn_obs.link_to(url_obs, "ASN-Url", self.name)

taskmanager.TaskManager.register_task(FutexTracker)

        