import logging
from dateutil import parser
from datetime import timedelta, datetime
from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError


class FeodoTrackerIPBlockList(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "FeodoTrackerIPBlocklist",
        "source": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description":
            "Feodo Tracker IP Feed. This feed shows a full list C2s.",
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar='"'):
            if not line or line[0].startswith("#"):
                continue

            first_seen, c2_ip, c2_port, last_online, family = tuple(line)
            first_seen = parser.parse(first_seen)

            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(line, first_seen, c2_ip, c2_port, last_online, family)

    def analyze(self, line, first_seen, c2_ip, c2_port, last_online, family):

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
