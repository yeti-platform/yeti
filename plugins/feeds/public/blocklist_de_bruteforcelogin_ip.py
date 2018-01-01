import logging
from datetime import timedelta

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class BlocklistdeBruteForceLoginIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://lists.blocklist.de/lists/bruteforcelogin.txt',
        'name': 'BlocklistdeBruteForceLoginIP',
        'description': 'Blocklist.de Brute Force Login IP Blocklist: All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins'
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
                ip.tag(['blocklist', 'bruteforce', 'web-logins', 'wordpress', 'joomla'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
