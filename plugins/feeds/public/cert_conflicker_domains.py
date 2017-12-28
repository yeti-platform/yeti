from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class CertConflickerDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=24),
        'source': 'http://www.cert.at/static/downloads/data/conficker/all_domains.txt',
        'name': 'CertConflickerDomains',
        'description': 'CERT (Computer Emergency Response Team) Austria Conflicker Domains'
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

            hostname = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                hostname = Hostname.get_or_create(value=hostname)
                hostname.add_context(context)
                hostname.add_source('feed')
                hostname.tag(['conflicker'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
