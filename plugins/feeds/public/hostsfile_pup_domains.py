from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class HostsFilePuPDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://hosts-file.net/pup.txt',
        'name': 'HostsFilePuPDomains',
        'description': 'Contains PuP (Potentially Unwanted Programs) sites listed in the hpHosts database by Domain.'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            hostname = str(parts[1]).strip()
            context = {
                'source': self.name
            }

            try:
                host = Hostname.get_or_create(value=hostname)
                host.add_context(context)
                host.add_source('feed')
                host.tag(['pup'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
