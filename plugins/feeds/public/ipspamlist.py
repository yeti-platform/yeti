import logging
from datetime import datetime, timedelta

from dateutil import parser

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


class IPSpamList(Feed):
    default_values = {
        "frequency": timedelta(days=1),
        "name": "IPSpamList",
        "source": "http://www.ipspamlist.com/public_feeds.csv",
        "description":
            "Service provided by NoVirusThanks that keeps track of malicious "
            "IP addresses engaged in hacking attempts, spam comments"
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar=None):
            if not line or line[0].startswith(('first_seen', '#')):
                continue

            first_seen = parser.parse(line[0])

            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(line, first_seen)

    def analyze(self, line, first_seen):

        first_seen, last_seen, ip_address, category, attacks_count = line

        context = {
            'source': self.name,
            'threat': category,
            'first_seen': first_seen,
            'last_seen': parser.parse(last_seen),
            'attack_count': attacks_count,
        }

        try:
            ip_obs = Ip.get_or_create(value=ip_address)
            ip_obs.tag(category)
            ip_obs.add_source(self.name)
            ip_obs.add_context(context)
        except ObservableValidationError as e:
            logging.error('Error in IP format %s %s' % (ip_address, e))
            return False
