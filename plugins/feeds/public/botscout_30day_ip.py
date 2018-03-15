from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class Botscout1DayIP(Feed):
    default_values = {
        'frequency': timedelta(minutes=45),
        'source': 'https://iplists.firehol.org/files/botscout_1d.ipset',
        'name': 'Botscout1DayIP',
        'description': 'BotScout is a service that helps fight automated web scripts, also known as "bots". Bots mindlessly roam the web looking for forms to fill out and submit in order to spread thei spam, drop links, and also to gain admittance to a site so they can find and exploit additional forms. The result of all of this includes bogus registrations on forums, pollution of your carefully-developed database(s), offensive link spam, and numerous other problems.'
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
                ip.tag(['blocklist'], ['abuse'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
