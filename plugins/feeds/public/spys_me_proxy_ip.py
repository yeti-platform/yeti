from datetime import timedelta
import logging

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class SpyMeAnonProxyIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'http://spys.me/proxy.txt',
        'name': 'SpyMeAnonProxyIP',
        'description': 'Spy.me Anonymous Proxy List: IP address:Port Country-Anonymity(Noa/Anm/Hia)-SSL_support(S)-Google_passed(+).'

    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            line = line.replace(":", " ")
            parts = line.split()
            ip = str(parts[0])
            port = str(parts[1])
            spycountry = str(parts[2])
            spygoogle = str(parts[3])
            context = {
                'source': self.name,
                'port': port,
                'country_anon_ssl': spycountry,
                'google_passed': spygoogle
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['anonproxy'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
