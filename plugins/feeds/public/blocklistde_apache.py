import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeApache(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeApache",
        "source": " https://lists.blocklist.de/lists/apache.txt",
        "description": "All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.",
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
            obs.tag("apache")
        except ObservableValidationError as e:
            raise logging.error(e)
