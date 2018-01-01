from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class StopFourmSpamDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt',
        'name': 'StopFourmSpamDomains',
        'description': 'StopFourmSpam.com SPAM Domain Blacklist.'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            hostname = str(parts[0])
            context = {
                'source': self.name
            }

            try:
                hostname = Hostname.get_or_create(value=hostname)
                hostname.add_context(context)
                hostname.add_source('feed')
                hostname.tag(['spam', 'blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
