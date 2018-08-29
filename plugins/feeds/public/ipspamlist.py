import logging
from datetime import timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


class IPSpamList(Feed):
    default_values = {
        "frequency":
            timedelta(days=1),
        "name":
            "IPSpamList",
        "source":
            "http://www.ipspamlist.com/public_feeds.csv",
        "description":
            "Service provided by NoVirusThanks that keeps track of malicious "
            "IP addresses engaged in hacking attempts, spam comments"
    }

    def update(self):
        for line in self.update_csv(delimiter=',', quotechar=None):
            self.analyze(line)

    def analyze(self, item):
        if not item or item[0].startswith('first_seen'):
            return
        try:
            context = dict(source=self.name)
            first_seen, last_seen, ip_address, category, attacks_count = item

            try:
                ip = Ip.get_or_create(value=ip_address)
            except ObservableValidationError as e:
                logging.error('Error IP format %s %e' % (ip_address, e))
                return False

            context['threat'] = category
            ip.tag(category)

            context['first_seen'] = first_seen

            context['last_seen'] = last_seen

            context['attack_count'] = attacks_count

            ip.add_source('feed')

            ip.add_context(context)

        except Exception as e:
            logging.error('Error to process the line %s %s' % (item, e))
            return False
        return True
