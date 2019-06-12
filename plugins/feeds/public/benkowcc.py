import csv
import logging
from dateutil import parser
from datetime import datetime, timedelta

from core.observables import Url, Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class BenkowTracker(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BenkowTracker",
        "source": "http://benkow.cc/export.php",
        "description": "This feed contains known Malware C2 servers",
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        resp = self._make_request()
        reader = csv.reader(
            resp.content.strip().splitlines(), delimiter=';', quotechar='"')

        for line in reader:
            if line[0] == 'id':
                return

            first_seen = parser.parse(line[4])

            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(line, first_seen)

    def analyze(self, line, first_seen):

        url_obs = False

        #TODO(doomedraven) id seems not to be used elsewhere, please replace with _ if that's indended
        id, family, url, ip, first_seen, _ = line
        context = {}
        context['date_added'] = first_seen
        context['source'] = self.name

        tags = []
        tags.append(family.lower())

        try:
            if url:
                url_obs = Url.get_or_create(value=url)
                url_obs.add_context(context)
                url_obs.add_source(self.name)
                url_obs.tag(tags)

        except ObservableValidationError as e:
            logging.error(e)

        try:
            if ip:
                ip_obs = Ip.get_or_create(value=ip)
                ip_obs.add_context(context)
                ip_obs.add_source(self.name)
                ip_obs.tag(tags)
                if url_obs:
                    ip_obs.active_link_to(
                        url_obs, "url", self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
