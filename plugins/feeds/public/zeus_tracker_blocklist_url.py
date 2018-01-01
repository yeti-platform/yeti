from datetime import timedelta
import logging

from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError


class ZeusCompromisedURL(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'name': 'ZeusCompromisedURL',
        'source': 'https://zeustracker.abuse.ch/blocklist.php?download=compromised',
        'description': 'Zeus Tracker URL Blocklist'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, data):
        if data.startswith('[a-zA-Z0-9]'):
            if len(data) > 1023:
                logging.info('URL is too long for mongo db. url=%s' % str(data))
            else:
                tags = ['zeus', 'objective', 'banker', 'crimeware', 'malware']

                context = {
                    'source': self.name
                }

                try:
                    url = Url.get_or_create(value=data.rstrip())
                    url.add_context(context)
                    url.add_source('feed')
                    url.tag(tags)
                except ObservableValidationError as e:
                    logging.error(e)
