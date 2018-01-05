from datetime import timedelta
import logging

from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError


class VXVaultUrl(Feed):

    # set default values for feed
    default_values = {
        'frequency': timedelta(hours=1),
        'name': 'VXVaultUrl',
        'source': 'http://vxvault.net/URL_List.php',
        'description': 'VXVault Community URL list.'
    }

    # should tell yeti how to get and chunk the feed
    def update(self):
        # Using update_lines because the pull should result in
        # a list of URLs, 1 per line. Split on newline
        for line in self.update_lines():
            self.analyze(line)

    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def analyze(self, data):
        if data.startswith('http'):
            if len(data) > 1023:
                logging.info('URL is too long for mongo db. url=%s' % str(data))
            else:
                tags = ['malware']

                context = {'source': self.name}

                try:
                    url = Url.get_or_create(value=data.rstrip())
                    url.add_context(context)
                    url.add_source('feed')
                    url.tag(tags)
                except ObservableValidationError as e:
                    logging.error(e)
