from datetime import datetime, timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class CyberSweatShopIMAPSIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://cybersweat.shop/iprep/iprep_imaps.txt',
        'name': 'CyberSweatShopIMAPSIP',
        'description': 'CyberSweatShop; IP addresses have been detected as a result of a failed login to the IMAPS server'
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

            ip = str(parts[3]).strip()
            last_seen = str(parts[0:3]).encode('utf-8').strip()
            username = str(parts[4]).strip()
            context = {
                'source': self.name,
                'last_seen': last_seen,
                'username': username
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist', 'imaps', 'honeypot'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
