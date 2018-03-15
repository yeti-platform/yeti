from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class MalcodeZonefileDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'http://malc0de.com/bl/ZONES',
        'name': 'MalcodeZoneFileDomains',
        'description': 'Malc0de Bind Zone File: Domains serving malicious executables observed by malc0de.com/database/'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('//'):
            return

        try:
            parts = line.split()
            hostname = str(parts[1])
            context = {
                'source': self.name
            }

            try:
                hostname = Hostname.get_or_create(value=hostname)
                hostname.add_context(context)
                hostname.add_source('feed')
                hostname.tag(['blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)