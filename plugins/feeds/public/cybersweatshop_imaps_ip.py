from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class CyberSweatShopIMAPSIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://cybersweat.shop/iprep/iprep_imaps.txt',
        'name': 'CyberSweatShopIMAPSIP',
        'description': 'CyberSweatShop: IP addresses that have been detected as a result of a failed login to IMAPS servers.'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            ip = str(parts[3])
            last_seen = str(parts[0:3]).encode('utf-8')
            username = str(parts[4])
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
