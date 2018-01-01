import datetime
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class YoyoAdserversIP(Feed):
    default_values = {
        'frequency': datetime.timedelta(hours=4),
        'name': 'YoyoAdserversIP',
        'source': 'https://pgl.yoyo.org/adservers/iplist.php?format=plain&showintro=0',
        'description': 'pgl.yoyo.org list of Addservers'
    }

    def update(self):
        for ip in self.update_lines():
            self.analyze(ip)

    def analyze(self, line):
        if not line.startswith('\d'):
            return

        try:
            parts = line.split()
            ip = str(parts[1])
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['addserver'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
