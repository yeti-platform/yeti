import logging
from datetime import timedelta, datetime
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeStrongIPs(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeStrongIPs",
        "source": "https://lists.blocklist.de/lists/strongips.txt",
        "description": "All IPs which are older then 2 month and have more then 5.000 attacks.",
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        ip = line.strip()

        context = {"source": self.name, "date_added": datetime.utcnow()}

        try:
            obs = Ip.get_or_create(value=ip)
            obs.add_context(context, dedup_list=["date_added"])
            obs.add_source(self.name)
            obs.tag("blocklistde")
            obs.tag("confident")
        except ObservableValidationError as e:
            logging.error(e)
