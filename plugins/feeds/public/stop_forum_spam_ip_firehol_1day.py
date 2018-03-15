from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class StopforumspamIPFirehol1Day(Feed):
    default_values = {
        'frequency': timedelta(hours=12),
        'source': 'https://iplists.firehol.org/files/stopforumspam_1d.ipset',
        'name': 'StopforumspamIPFirehol1Day',
        'description': "StopForumSpam.com IPs used by forum spammers in the last 24 hours."
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
