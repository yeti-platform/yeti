import logging
from dateutil import parser
from datetime import timedelta, datetime

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Url, Ip


class ViriBackTracker(Feed):
    default_values = {
        "frequency": timedelta(hours=24),
        "name": "ViriBackTracker",
        "source": "http://tracker.viriback.com/dump.php",
        "description":
            "Malware C2 Urls and IPs",
    }

    def update(self):
        since_last_run = datetime.utcnow() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar='"'):
            if not line or line[0].startswith(("Family", "#")):
                continue

            family, url, ip, first_seen = line
            first_seen = parser.parse(first_seen)
            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(family, url, ip, first_seen)

    def analyze(self, family, url, ip, first_seen):

        url_obs = False
        ip_obs = False

        family = family.lower()
        context = {
            'first_seen': first_seen,
            'source': self.name
        }

        if url:
            try:
                url_obs = Url.get_or_create(value=url)
                url_obs.add_context(context)
                url_obs.add_source(self.name)
                url_obs.tag(["c2", family])
            except ObservableValidationError as e:
                logging.error(e)

        if ip:
            try:
                ip_obs = Ip.get_or_create(value=ip)
                ip_obs.add_context(context)
                ip_obs.tag(family.lower())
            except ObservableValidationError as e:
                logging.error(e)

        if url_obs and ip_obs:
            url_obs.active_link_to(ip_obs, 'ip', self.name)
