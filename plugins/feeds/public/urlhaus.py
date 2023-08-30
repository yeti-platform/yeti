import logging
import pandas as pd
from io import StringIO
from datetime import timedelta
from core.schemas import observable
from core.schemas import task
from core import taskmanager


class UrlHaus(task.FeedTask):
    _defaults = {
        "frequency": timedelta(minutes=20),
        "name": "UrlHaus",
        "description": "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }
    SOURCE = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    _NAMES = [
        "id",
        "dateadded",
        "url",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter",
    ]

    def run(self):
        response = self._make_request(self.SOURCE, auth=None)
        if response:
            data = response.text

            df = pd.read_csv(
                StringIO(data),
                comment="#",
                delimiter=",",
                names=self._NAMES,
                quotechar='"',
                quoting=True,
                skipinitialspace=True,
                parse_dates=["dateadded", "last_online"],
                header=0,
            )
            df = self._filter_observables_by_time(df, "dateadded")
            df.fillna("", inplace=True)

            for _, line in df.iterrows():
                self.analyze(line)

    def analyze(self, line):
        id_feed = line["id"]
        first_seen = line["dateadded"]
        url = line["url"]
        url_status = line["url_status"]
        last_online = line["last_online"]
        threat = line["threat"]
        tags = line["tags"]
        urlhaus_link = line["urlhaus_link"]
        source = line["reporter"]

        context = {
            "id_urlhaus": id_feed,
            "status": url_status,
            "source": self.name,
            "report": urlhaus_link,
            "threat": threat,
            "reporter": source,
            "first_seen": first_seen,
            "last_online": last_online,
        }

        if url:
            obs = observable.Observable.find(value=url)
            if not obs:
                obs = observable.Observable(value=url, type="url")
            obs.add_context(self.name, context)
            obs.tag(tags)

taskmanager.TaskManager.register_task(UrlHaus)
