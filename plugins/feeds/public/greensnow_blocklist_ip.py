import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class GreensnowBlocklistIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://blocklist.greensnow.co/greensnow.txt',
        'name': 'GreensnowBlocklistIP',
        'description': 'GreenSnow is a team consisting of the best specialists in computer security, we harvest a large number of IPs from different computers located around the world. GreenSnow is comparable with SpamHaus.org for attacks of any kind except for spam. Attacks / bruteforce that are monitored are: Scan Port, FTP, POP3, mod_security, IMAP, SMTP, SSH, cPanel ...'
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

            ip = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
