import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class BlocklistdeBOTip(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://lists.blocklist.de/lists/bots.txt',
        'name': 'BlocklistdeBOTip',
        'description': 'Blocklist.de BOTS IP Blocklist: All IP addresses which have been reported within the last 48 hours as having run attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).'
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
                ip.tag(['blocklist', 'bot', 'irc-bot', 'reg-bot'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
