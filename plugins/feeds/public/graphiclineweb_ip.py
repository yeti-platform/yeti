from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class GPFComicsIP(Feed):
    default_values = {
        'frequency': timedelta(hours=24),
        'source': 'https://iplists.firehol.org/files/gpf_comics.ipset',
        'name': 'GPFComicsIP',
        'description': 'The GPF DNS Block List is a list of IP addresses on the Internet that have attacked the GPF Comics family of Web sites. IPs on this block list have been banned from accessing all of our servers because they were caught in the act of spamming, attempting to exploit our scripts, scanning for vulnerabilities, or consuming resources to the detriment of our human visitors.'
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
