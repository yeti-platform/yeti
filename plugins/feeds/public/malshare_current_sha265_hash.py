from datetime import timedelta
import logging

from core.observables import Hash
from core.feed import Feed
from core.errors import ObservableValidationError


class MalshareCurrentSHA256(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'http://www.malshare.com/daily/malshare.current.sha256.txt',
        'name': 'MalshareCurrentSHA256',
        'description': 'Malshare Current List SHA256 Hashes'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split()
            malhash = str(parts[0])
            context = {
                'source': self.name
            }

            try:
                malhash = Hash.get_or_create(value=malhash)
                malhash.add_context(context)
                malhash.add_source('feed')
                malhash.tag(['malware'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
