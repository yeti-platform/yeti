import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeIRCBot(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeIRCBot",
        "source": "https://lists.blocklist.de/lists/ircbot.txt",
        "description": "Deprecated feed",
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
            obs.tag("irc")
            obs.tag("bot")
        except ObservableValidationError as e:
            raise logging.error(e)
