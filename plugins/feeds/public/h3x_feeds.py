import csv
import logging
from dateutil import parser
from datetime import datetime, timedelta

from core.feed import Feed
from core.observables import Url
from core.errors import ObservableValidationError


class MalwareCorpusTracker(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "MalwareCorpusTracker",
        "source": "http://tracker.h3x.eu/api/sites_1day.php",
        "description": "This feed contains known Malware C2 servers",
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        resp = self._make_request()
        reader = csv.reader(resp.content.splitlines(), quotechar='"')
        for line in reader:
            if line[0].startswith('#'):
                continue

            first_seen = parser.parse(line[4])

            if self.last_run is not None:
                if since_last_run > first_seen.replace(tzinfo=None):
                    return

            self.analyze(line, first_seen)

    # pylint: disable=arguments-differ
    def analyze(self, line, first_seen):

        # split the entry into observables
        # pylint: disable=line-too-long
        family, type_, url, status, _, first_active, last_cctive, last_seen = line

        context = {}
        context['status'] = status
        context['date_added'] = first_seen
        context['last_seen'] = last_seen
        context['source'] = self.name

        tags = []
        tags.append(family.lower())
        tags.append(type_.lower())

        try:
            url = Url.get_or_create(value=url)
            url.add_context(context)
            url.add_source(self.name)
            url.tag(tags)
        except ObservableValidationError as e:
            logging.error(e)
