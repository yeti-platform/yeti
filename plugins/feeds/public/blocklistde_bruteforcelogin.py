import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeBruteforceLogin(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeBruteforceLogin",
        "source": "https://lists.blocklist.de/lists/bruteforcelogin.txt",
        "description": "All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.",
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
            obs.tag("bruteforce")
        except ObservableValidationError as e:
            raise logging.error(e)
