from datetime import timedelta
import logging

from core.feed import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


class CyberSweatShopMailIP(Feed):
    default_values = {
        "frequency": timedelta(hours=1),
        "name": "CyberSweatShopMailIP",
        "source": "https://cybersweat.shop/iprep/iprep_mail.txt",
        "description": "CyberSweatShop: IP addresses have been detected performing behavior not in compliance within the requirements for proper email acceptance.",
    }

    def update(self):
        for line in self.update_csv(delimiter=';', quotechar='-'):
            self.analyze(line)

        self.source = self.default_values['source']

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        try:
            ip, last_seen, details = tuple(map(strip, line))
            context = {
                "last_seen": last_seen,
                "details": details,
                "source": self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist', 'spam', 'honeypot'])
            except ObservableValidationError as e:
                logging.error("Invalid line: {}\nLine: {}".format(e, line))

        except ValueError:
            logging.error("Error unpacking line: {}".format(line))
