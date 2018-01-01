from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class HostsFileHosts(Feed):
    default_values = {
        'frequency': timedelta(hours=24),
        'source': 'http://issviews.com/hphosts/hosts.txt',
        'name': 'HostsFileHosts',
        'description': 'Contains sites assoicated in; malware, fraud, phishing, spam, exploits, and/or phrama.  Contents come from hpHosts database by Domain.'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            hostname = str(parts[1])
            context = {
                'source': self.name
            }

            try:
                host = Hostname.get_or_create(value=hostname)
                host.add_context(context)
                host.add_source('feed')
                host.tag(['malware', 'fraud', 'phishing', 'spam', 'exploits', 'pharma'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
