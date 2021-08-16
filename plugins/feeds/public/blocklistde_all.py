import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeAll(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeAll",
        "source": "https://lists.blocklist.de/lists/all.txt",
        "description": "All IP addresses that have attacked one of our customers/servers in the last 48 hours. It's not recommended to use this feed due to the lesser amount of contextual information, it's better to use each blocklist.de feed separately.",
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        ip = line.strip()

        context = {"source": self.name}

        try:
            obs = Ip.get_or_create(value=ip)
            obs.add_context(context)
            obs.add_source(self.name)
            obs.tag("blocklistde")
        except ObservableValidationError as e:
            raise logging.error(e)
