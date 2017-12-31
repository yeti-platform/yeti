from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class MalcodeBlocklistIP(Feed):
    default_values = {
        'frequency': timedelta(hours=4),
        'name': 'MalcodeBlocklistIP',
        'source': 'http://malc0de.com/bl/IP_Blacklist.txt',
        'description': 'This file will be automatically updated daily and populated with the last 30 days of malicious IP addresses.'
    }

    def update(self):
        for ip in self.update_lines():
            self.analyze(ip)

    def analyze(self, line):
        if line.startswith('//'):
            return
        try:
            line = line.strip()
            parts = line.split()
            ip = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist', 'malware'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
