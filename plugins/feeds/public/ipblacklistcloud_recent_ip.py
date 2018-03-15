from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class GraphiclinewebIP(Feed):
    default_values = {
        'frequency': timedelta(hours=24),
        'source': 'https://iplists.firehol.org/files/graphiclineweb.netset',
        'name': 'GraphiclinewebIP',
        'description': 'GraphiclineWeb The IPs, Hosts and Domains listed in this table are banned universally from accessing websites controlled by the maintainer. Some form of bad activity has been seen from the addresses listed. Bad activity includes: unwanted spiders, rule breakers, comment spammers, trackback spammers, spambots, hacker bots, registration bots and other scripting attackers, harvesters, nuisance spiders, spy bots and organisations spying on websites for commercial reasons.'
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
