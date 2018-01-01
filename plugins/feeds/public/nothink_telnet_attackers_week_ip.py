from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class NoThinkTelnetAttackerWeekIP(Feed):
    default_values = {
        'frequency': timedelta(hours=4),
        'name': 'NoThinkTelnetAttackerWeekIP',
        'source': 'http://www.nothink.org/blacklist/blacklist_telnet_week.txt',
        'description': 'Telnet blacklists (updated every day and in text format) contains IP addresses of hosts which tried to bruteforce into my honeypot located in Italy. The honeypot simulates a home router with a weak password.'
    }

    def update(self):
        for ip in self.update_lines():
            self.analyze(ip)

    def analyze(self, line):
        if line.startswith('#'):
            return
        try:
            parts = line.split()
            ip = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['telnet', 'bruteforce', 'attacker', 'honeypot', 'blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
