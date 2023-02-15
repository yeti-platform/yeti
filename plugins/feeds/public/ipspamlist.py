import logging
from datetime import timedelta, datetime

from dateutil import parser

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


class IPSpamList(Feed):
    default_values = {
        "frequency": timedelta(days=1),
        "name": "IPSpamList",
        "source": "http://www.ipspamlist.com/public_feeds.csv",
        "description": "Service provided by NoVirusThanks that keeps track of malicious "
        "IP addresses engaged in hacking attempts, spam comments",
    }

    def update(self):
        for index, line in self.update_csv(delimiter=",", filter_row="first_seen"):
            self.analyze(line)

    def analyze(self, item):
        context = {
            "source": self.name,
            "threat": item["category"],
            "first_seen": item["first_seen"],
            "last_seen": parser.parse(item["last_seen"]),
            "attack_count": item["attacks_count"],
            "date_added": datetime.utcnow(),
        }
        ip_address = item["ip_address"]
        try:
            ip_obs = Ip.get_or_create(value=ip_address)
            ip_obs.tag(context["threat"])
            ip_obs.add_source(self.name)
            ip_obs.add_context(context, dedup_list=["date_added"])
        except ObservableValidationError as e:
            logging.error("Error in IP format %s %s" % (ip_address, e))
