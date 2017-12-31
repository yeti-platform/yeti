from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class JoeweinSpamBlocklistDomain(Feed):
    default_values = {
        'frequency': timedelta(hours=4),
        'source': 'http://www.joewein.net/dl/bl/dom-bl-base.txt',
        'name': 'JoeweinSpamBlocklistDomain',
        'description': 'Information about domains that have been advertised via spam ("spamvertized"). Every domain listed has appeared inside unsolicited bulk email, either advertised or as a genuine return address or both.'

    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split(';')
            hostname = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                host = Hostname.get_or_create(value=hostname)
                host.add_context(context)
                host.add_source('feed')
                host.tag(['spam'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
