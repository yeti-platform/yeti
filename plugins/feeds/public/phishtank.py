import logging
from dateutil import parser
from datetime import timedelta, datetime

from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError


class PhishTank(Feed):

    # set default values for feed
    default_values = {
        'frequency': timedelta(hours=4),
        'name': 'PhishTank',
        'source': 'http://data.phishtank.com/data/online-valid.csv',
        'description':
            'PhishTank community feed. Contains a list of possible Phishing URLs.'
    }

    # should tell yeti how to get and chunk the feed
    def update(self):
        # Using update_lines because the pull should result in
        # a list of URLs, 1 per line. Split on newline

        since_last_run = datetime.now() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar='"'):
            if not line or line[0].startswith('phish_id'):
                continue

            first_seen = parser.parse(line[3])
            if self.last_run is not None:
                if since_last_run > first_seen.replace(tzinfo=None):
                    return

            self.analyze(line, first_seen)

    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def analyze(self, data, first_seen):

        _, url, phish_detail_url, _, verified, verification_time, online, target = tuple(
            data)

        tags = ['phishing']

        context = {
            'source': self.name,
            'phish_detail_url': phish_detail_url,
            'submission_time': first_seen,
            'verified': verified,
            'verification_time': verification_time,
            'online': online,
            'target': target
        }

        if url is not None and url != '':
            try:
                url = Url.get_or_create(value=url)
                url.add_context(context)
                url.add_source(self.name)
                url.tag(tags)
            except ObservableValidationError as e:
                logging.error(e)
