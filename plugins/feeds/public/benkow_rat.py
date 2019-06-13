import csv
import logging
from datetime import datetime, timedelta

from dateutil import parser

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip, Url


class BenkowTrackerRat(Feed):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "BenkowTrackerRat",
        "source": "http://benkow.cc/export_rat.php",
        "description": "This feed contains known Malware C2 servers",
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        resp = self._make_request()
        reader = csv.reader(resp.content.strip().splitlines(), delimiter=';', quotechar='"')
        for line in reader:
            if line[0] == 'id':
                return

            first_seen = parser.parse(line[4])

            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(line, first_seen)

    def analyze(self, line, first_seen):

        context = {}
        context['date_added'] = first_seen
        context['source'] = self.name

        id, family, url, ip, first_seen, _ = line

        if not url.startswith(('http://', 'https://')):
            url = "http://" + url

        tags = []
        tags.append(family.lower())
        tags.append("rat")

        try:
            if url:
                url = Url.get_or_create(value=url)
                url.add_context(context)
                url.add_source(self.name)
                url.tag(tags)

        except ObservableValidationError as e:
            logging.error(e)

        try:
            if ip:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source(self.name)
                ip.tag(tags)

        except ObservableValidationError as e:
            logging.error(e)
