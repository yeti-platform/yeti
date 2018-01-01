import datetime
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class ZeusTrackerBlocklistIP(Feed):
    default_values = {
        'frequency': datetime.timedelta(hours=1),
        'source': 'https://zeustracker.abuse.ch/blocklist.php?download=badips',
        'name': 'ZeusTrackerBlocklistIP',
        'description': 'abuse.ch ZeuS IP blocklist "BadIPs" (excluding hijacked sites and free hosting providers)'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            ip = str(parts[0])
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['zeus', 'objective', 'banker', 'crimeware', 'malware'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
