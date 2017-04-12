from datetime import timedelta
import logging

from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError

class PhishTank(Feed):

    # set default values for feed
    default_values = {
        'frequency': timedelta(hours=4),
        'name': 'PhishTank',
        'source': 'http://data.phishtank.com/data/online-valid.csv',
        'description': 'PhishTank community feed. Contains a list of possible Phishing URLs.'
    }

    # should tell yeti how to get and chunk the feed
    def update(self):
        # Using update_lines because the pull should result in
        # a list of URLs, 1 per line. Split on newline
        for line in self.update_csv(delimiter=',',quotechar='"'):
            self.analyze(line)


    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def analyze(self, data):
        if not data or data[0].startswith('phish_id'):
            return

        phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target = tuple(data)
        
        tags = ['phishing', 'phish']

        context = {
            'source': self.name,
            'phish_detail_url': phish_detail_url,
            'submission_time': submission_time,
            'verified': verified,
            'verification_time': verification_time,
            'online': online,
            'target': target
        }
        
        if url is not None and url != '':
            try:
                if len(url) > 1023:
                    logging.info('URL is too long for mongo db. url=%s' % str(url))
                else:		
                    url = Url.get_or_create(value=url)
                    url.add_context(context)
                    url.add_source('feed')
                    url.tag(tags)
            except ObservableValidationError as e:
                logging.error(e)
