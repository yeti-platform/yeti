import datetime
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class ZeusTrackerBlocklistDomains(Feed):
    default_values = {
        'frequency': datetime.timedelta(hours=1),
        'source': 'https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
        'name': 'ZeusTrackerBlocklistDomains',
        'description': 'abuse.ch ZeuS domain blocklist "BadDomains" (excluding hijacked sites)'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            hostname = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                hostname = Hostname.get_or_create(value=hostname)
                hostname.add_context(context)
                hostname.add_source('feed')
                hostname.tag(['zeus', 'objective', 'banker', 'crimeware', 'malware'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
