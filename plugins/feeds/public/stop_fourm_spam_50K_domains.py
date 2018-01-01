from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class StopFourmSpamFiltered50KDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://www.stopforumspam.com/downloads/toxic_domains_whole_filtered_50000.txt',
        'name': 'StopFourmSpamFiltered50KDomains',
        'description': 'StopFourmSpam.com SPAM Domain Blacklist. The data is an appendum to the main Domain list, as it provides a filtered version of the "toxic_domains_whole" file. The filtered data removees domains that appear in the Top 1,000,000 Alexa domains list.'
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
                hostname.tag(['spam', 'blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
