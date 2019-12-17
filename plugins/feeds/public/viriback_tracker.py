import logging
from datetime import timedelta

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
        for index, line in self.update_csv(delimiter=',', filter_row='FirstSeen',
                                    header=0):

            self.analyze(line)

    def analyze(self,line):

        url_obs = False
        ip_obs = False
        family = line['Family']
        url = line['URL']
        ip = line['IP']
        first_seen = line['FirstSeen']
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
