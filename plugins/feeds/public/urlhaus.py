import logging
from datetime import timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Url


class UrlHaus(Feed):
    default_values = {
        "frequency": timedelta(minutes=20),
        "name": "UrlHaus",
        "source": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }

    def update(self):

        for index, line in self.update_csv(
            delimiter=",",
            names=[
                "id",
                "dateadded",
                "url",
                "url_status",
                "last_online",
                "threat",
                "tags",
                "urlhaus_link",
                "reporter",
            ],
            filter_row="dateadded",
        ):
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
        source = line["reporter"]  # pylint: disable=line-too-long

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
            try:
                url_obs = Url.get_or_create(value=url)
                url_obs.tag(tags.split(","))
                url_obs.add_context(context)
                url_obs.add_source(self.name)
            except ObservableValidationError as e:
                logging.error(e)
