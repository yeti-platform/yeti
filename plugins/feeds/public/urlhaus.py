import logging
from datetime import timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Url


class UrlHaus(Feed):
    default_values = {
        "frequency":
            timedelta(minutes=20),
        "name":
            "UrlHaus",
        "source":
            "https://urlhaus.abuse.ch/downloads/csv/",
        "description":
            "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }

    def update(self):
        for line in self.update_csv(delimiter=',',quotechar='"'):
            self.analyze(line)

    def analyze(self, item):

        if not item or item[0].startswith("#"):
            return

        id_feed, dateadded, url, url_status, threat, tags, urlhaus_link, reporter = item

        context = {
            "id_urlhaus": id_feed,
            "first_seen": dateadded,
            "status": url_status,
            "source": self.name,
            "urlhaus_link": urlhaus_link,
            "reporter": reporter,
            "threat": threat
        }

        if url:
            try:
                url_obs = Url.get_or_create(value=url)
                url_obs.tag(tags.split(','))
                url_obs.add_context(context)
                url_obs.add_source('feed')
            except ObservableValidationError as e:
                logging.error(e)
