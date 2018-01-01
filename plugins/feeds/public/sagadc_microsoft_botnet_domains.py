from datetime import timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError


class SagadcMicrosoftBotnetDomains(Feed):
    default_values = {
        'frequency': timedelta(hours=4),
        'name': 'SagadcMicrosoftBotnetDomains',
        'source': 'http://dns-bh.sagadc.org/Microsoft-Botnet-domains-no-ip.txt',
        'description': 'SAGADC.org Microsoft Botnet Domains (Last updated in 2015)'
    }

    def update(self):
        for hostname in self.update_lines():
            self.analyze(hostname)

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
                hostname.tag(['botnet', 'microsoft', 'blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
