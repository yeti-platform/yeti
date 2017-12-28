import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class BlocklistdeStrongip(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://lists.blocklist.de/lists/strongips.txt',
        'name': 'BlocklistdeStrongip',
        'description': 'Blocklist.de Strong IP Blocklist: All IPs which are older then 2 month and have more then 5.000 attacks.'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            line = line.strip()
            parts = line.split()

            ip = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist', 'strong'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
