from datetime import timedelta
import logging

from core.feed import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


class NothinkTelnetIP(Feed):
    default_values = {
        "frequency": timedelta(hours=4),
        "name": "NothinkTelnetIP",
        "source": "http://www.nothink.org/honeypot_telnet_hits.txt",
        "description": "Telnet blacklists (updated every day and in text format) contains IP addresses of hosts which tried to bruteforce into my honeypot located in Italy. The honeypot simulates a home router with a weak password",
    }

    def update(self):
        for line in self.update_csv(delimiter=',', quotechar='"'):
            self.analyze(line)

        self.source = self.default_values['source']

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        try:
            date, ip = tuple(line)
            context = {
                "last_seen": date,
                "source": self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['telnet', 'bruteforce', 'attacker', 'honeypot', 'portscan', 'blocklist'])
            except ObservableValidationError as e:
                logging.error("Invalid line: {}\nLine: {}".format(e, line))

        except ValueError:
            logging.error("Error unpacking line: {}".format(line))
