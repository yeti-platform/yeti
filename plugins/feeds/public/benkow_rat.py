import logging
from datetime import timedelta

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
        for index, line in self.update_csv(filter_row='date', delimiter=';',
                                           date_parser=['date'], header=0):
            self.analyze(line)

    def analyze(self, line):

        context = {}
        context['date_added'] = line['date']
        context['source'] = self.name

        family = line['type']
        url = line['url']
        ip = line['ip']

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
