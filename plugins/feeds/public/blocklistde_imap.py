import logging
from datetime import timedelta, datetime
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeIMAP(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeIMAP",
        "source": "https://lists.blocklist.de/lists/imap.txt",
        "description": "All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3.....",
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, item):
        ip = item.strip()

        context = {"source": self.name, "date_added": datetime.utcnow()}

        try:
            obs = Ip.get_or_create(value=ip)
            obs.add_context(context, dedup_list=["date_added"])
            obs.add_source(self.name)
            obs.tag("blocklistde")
            obs.tag("imap")
        except ObservableValidationError as e:
            logging.error(e)
