import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeSSH(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeSSH",
        "source": "https://lists.blocklist.de/lists/ssh.txt",
        "description": "All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.",
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
            obs.tag("ssh")
        except ObservableValidationError as e:
            raise logging.error(e)
