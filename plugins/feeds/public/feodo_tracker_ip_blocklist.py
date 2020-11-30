import logging
from datetime import timedelta

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url


class FeodoTrackerIPBlockList(Feed):
    default_values = {
        "frequency": timedelta(hours=24),
        "name": "FeodoTrackerIPBlocklist",
        "source": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description": "Feodo Tracker IP Feed. This feed shows a full list C2s.",
    }

    def update(self):

        for index, line in self.update_csv(
            delimiter=",",
            filter_row="Firstseen",
            names=["Firstseen", "DstIP", "DstPort", "LastOnline", "Malware"],
        ):
            self.analyze(line)

    # pylint: disable=arguments-differ
    def analyze(self, line):

        tags = []
        tags.append(line["Malware"].lower())
        tags.append("c2")
        tags.append("blocklist")

        context = {
            "first_seen": line["Firstseen"],
            "source": self.name,
            "last_online": line["LastOnline"],
        }

        try:
            new_url = Url.get_or_create(
                value="http://{}:{}/".format(line["DstIP"], line["DstPort"])
            )
            new_url.add_context(context, dedup_list=["last_online"])
            new_url.tag(tags)

        except ObservableValidationError as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))
