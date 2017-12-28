import logging
from datetime import timedelta

from core.feed import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


def strip(str):
    return str.strip()


class CyberSweatShopMailIP(Feed):
    default_values = {
        "frequency": timedelta(minutes=60),
        "name": "CyberSweatShopMailIP",
        "source": "https://cybersweat.shop/iprep/iprep_mail.txt",
        "description": "CyberSweatShop; IP addresses have been detected performing behavior not in compliance with the requirements this system enforces for email acceptance.",
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
