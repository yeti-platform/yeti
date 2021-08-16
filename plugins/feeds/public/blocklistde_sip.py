import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeSIP(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeSIP",
        "source": "https://lists.blocklist.de/lists/sip.txt",
        "description": "All IP addresses that tried to login in a SIP-, VOIP- or Asterisk-Server and are inclueded in the IPs-List from http://www.infiltrated.net/ (Twitter).",
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
            obs.tag("sip")
        except ObservableValidationError as e:
            raise logging.error(e)
