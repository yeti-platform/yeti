from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class BlocklistdeSIPip(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://lists.blocklist.de/lists/sip.txt',
        'name': 'BlocklistdeSIPip',
        'description': 'Blocklist.de SIP/VOIP IP Blocklist: All IP addresses that tried to login in a SIP, VOIP, or Asterisk-Server and are included in the IPs-List from http://www.infiltrated.net/ (Twitter)'

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
                ip.tag(['blocklist', 'voip', 'sip'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
