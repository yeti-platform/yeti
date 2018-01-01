from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class SagadcZeusGameoverDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=24),
        'name': 'SagadcZeusGameoverDomains',
        'source': 'http://dns-bh.sagadc.org/Zeus-Gameover.txt',
        'description': 'SAGADC.Org list Zeus Gameover Botnet Domains'
    }

    def update(self):
        for hostname in self.update_lines():
            self.analyze(hostname)

    def analyze(self, line):
        if line.startswith('#'):
            return
        try:
            hostname = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                hostname = Hostname.get_or_create(value=hostname)
                hostname.add_context(context)
                hostname.add_source('feed')
                hostname.tag(['botnet', 'zeus', 'blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
