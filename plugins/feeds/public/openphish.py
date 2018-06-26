from datetime import timedelta
import logging

from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError


class OpenPhish(Feed):

    # set default values for feed
    default_values = {
        'frequency':
            timedelta(hours=4),
        'name':
            'OpenPhish',
        'source':
            'https://openphish.com/feed.txt',
        'description':
            'OpenPhish community feed. Contains a list of possible Phishing URLs.'
    }

    # should tell yeti how to get and chunk the feed
    def update(self):
        # Using update_lines because the pull should result in
        # a list of URLs, 1 per line. Split on newline
        for url in self.update_lines():
            self.analyze(url)

    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def analyze(self, url):
        context = {'source': self.name}

        try:
            url = Url.get_or_create(value=url)
            url.add_context(context)
            url.add_source('feed')
            url.tag(['phishing'])
        except ObservableValidationError as e:
            logging.error(e)
