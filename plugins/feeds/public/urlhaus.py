import logging
from datetime import datetime, timedelta

from dateutil import parser

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Url


class UrlHaus(Feed):
    default_values = {
        "frequency": timedelta(minutes=20),
        "name": "UrlHaus",
        "source": "https://urlhaus.abuse.ch/downloads/csv/",
        "description":
            "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }

    def update(self):
        since_last_run = datetime.utcnow() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar='"'):
            if not line or line[0].startswith("#"):
                return

            first_seen = parser.parse(line[1])
            if self.last_run is not None:
                since_last_run = datetime.now() - self.frequency
                if since_last_run > first_seen:
                    return

            self.analyze(line)

    def analyze(self, line):

        id_feed, first_seen, url, url_status, threat, tags, urlhaus_link, source = line # pylint: disable=line-too-long

        context = {
            "id_urlhaus": id_feed,
            "status": url_status,
            "source": self.name,
            "report": urlhaus_link,
            "threat": threat,
            "reporter": source,
        }

        if url:
            try:
                url_obs = Url.get_or_create(value=url)
                url_obs.tag(tags.split(','))
                url_obs.add_context(context)
                url_obs.add_source(self.name)
            except ObservableValidationError as e:
                logging.error(e)
