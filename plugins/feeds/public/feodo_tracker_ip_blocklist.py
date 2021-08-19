import logging
from datetime import timedelta, datetime

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class FeodoTrackerIPBlockList(Feed):
    default_values = {
        "frequency": timedelta(hours=24),
        "name": "FeodoTrackerIPBlocklist",
        "source": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description": "Feodo Tracker IP Feed. This feed shows a full list C2s.",
    }

    def update(self):
        firs_line = 0
        for index, line in self.update_csv(
            delimiter=",",
            filter_row="first_seen_utc",
        ):
            if firs_line != 0:
                self.analyze(line)
            firs_line += 1

    # pylint: disable=arguments-differ
    def analyze(self, line):

        tags = []
        tags.append(line["malware"].lower())
        tags.append("c2")
        tags.append("blocklist")

        context = {
            "first_seen": line["first_seen_utc"],
            "source": self.name,
            "last_online": line["last_online"],
            "c2_status": line["c2_status"],
            "port": line["dst_port"],
            "date_added": datetime.utcnow(),
        }

        try:
            ip_obs = Ip.get_or_create(value=line["dst_ip"])
            ip_obs.add_context(context, dedup_list=["last_online","date_added"])
            ip_obs.tag(tags)

        except ObservableValidationError as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))
