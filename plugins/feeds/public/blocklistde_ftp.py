import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeFTP(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeFTP",
        "source": "https://lists.blocklist.de/lists/ftp.txt",
        "description": "All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.",
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        line = line.strip()

        ip = line

        context = {"source": self.name}

        try:
            obs = Ip.get_or_create(value=ip)
            obs.add_context(context)
            obs.add_source(self.name)
            obs.tag("blocklistde")
            obs.tag("ftp")
        except ObservableValidationError as e:
            raise logging.error(e)
