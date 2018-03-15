from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class BlocklistdeAllIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://lists.blocklist.de/lists/all.txt',
        'name': 'BlocklistdeAllIP',
        'description': 'Blocklist.de: All IP addresses that have attacked one of Blocklist.de customers/servers in the last 48 hours'
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
                ip.tag(['blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
