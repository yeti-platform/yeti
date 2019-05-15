from datetime import timedelta
import logging

from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError


class FeodoTrackerIPBlockList(Feed):

    default_values = {
        "frequency":
            timedelta(hours=24),
        "name":
            "FeodoTrackerIPBlocklist",
        "source":
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description":
            "Feodo Tracker IP Feed. This feed shows a full list C2s.",
    }

    def update(self):
        for line in self.update_csv(delimiter=',', quotechar='"'):
            self.analyze(line)

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        first_seen, c2_ip, c2_port, last_online, family = tuple(line)

        tags = []
        tags.append(family.lower())
        tags.append("c2")
        tags.append("blocklist")

        context = {
            "first_seen": first_seen,
            "source": self.name,
            "last_online": last_online,
        }

        try:
            new_url = Url.get_or_create(value="http://{}:{}/".format(
                c2_ip, c2_port)
            )
            new_url.add_context(context, dedup_list=["last_online"])
            new_url.tag(tags)

        except ObservableValidationError as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))
