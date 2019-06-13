import logging
from datetime import datetime, timedelta

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class HostsFileFSA(Feed):
    default_values = {
        'frequency': timedelta(hours=4),
        'source': 'https://hosts-file.net/fsa.txt',
        'name': 'HostsFileFSA',
        'description':
            'Sites engaged in the selling or distribution of bogus or fraudulent applications and/or provision of fraudulent services.'
    }

    def update(self):
        for line in self.update_lines():
            if line.startswith('#'):
                continue

            self.analyze(line)

    def analyze(self, line):
        try:
            line = line.strip()
            parts = line.split()

            hostname = str(parts[1]).strip()
            context = {'source': self.name}

            try:
                host = Hostname.get_or_create(value=hostname)
                host.add_context(context)
                host.add_source(self.name)
                host.tag(['fraud', 'blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
