from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class FireholAbusers1dayIP(Feed):
    default_values = {
        'frequency': timedelta(hours=24),
        'source': 'https://iplists.firehol.org/files/firehol_abusers_1d.netset',
        'name': 'FireholAbusers1dayIP',
        'description': 'An ipset made from blocklists that track abusers in the last 24 hours. (includes: botscout_1d cleantalk_new_1d cleantalk_updated_1d php_commenters_1d php_dictionary_1d php_harvesters_1d php_spammers_1d stopforumspam_1d).'
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
