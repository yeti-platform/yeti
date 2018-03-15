from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class IPBlacklistcloudRecentIP(Feed):
    default_values = {
        'frequency': timedelta(hours=24),
        'source': 'https://iplists.firehol.org/files/ipblacklistcloud_recent.ipset',
        'name': 'IPBlacklistcloudRecentIP',
        'description': "IP Blacklist Cloud These are the most recent IP addresses that have been blacklisted by websites. IP Blacklist Cloud plugin protects your WordPress based website from spam comments, gives details about login attacks which you don't even know are happening without this plugin!"
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            ip = str(parts[0])
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist','spam','abuse'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
