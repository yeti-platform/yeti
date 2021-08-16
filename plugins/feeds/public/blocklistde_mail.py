import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BlocklistdeMail(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeMail",
        "source": "https://lists.blocklist.de/lists/mail.txt",
        "description": "All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.",
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
            obs.tag("mail")
        except ObservableValidationError as e:
            raise logging.error(e)
