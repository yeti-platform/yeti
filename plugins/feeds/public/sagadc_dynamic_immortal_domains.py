from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class SagadcDynamicDNSDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=4),
        'name': 'SagadcDynamicDNSDomains',
        'source': 'http://dns-bh.sagadc.org/dynamic_dns.txt',
        'description': 'SAGADC.org list of Dynamic DNS names.  Not all are malicious, just used to enrich tagging against already seen domains. Tagged as dynamic_dns'
    }

    def update(self):
        for hostname in self.update_lines():
            self.analyze(hostname)

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
                hostname.tag(['dynamic dns', 'blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
