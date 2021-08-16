import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class Cruzit(Feed):

    default_values = {
        "frequency": timedelta(hours=13),
        "name": "Cruzit",
        "source": "https://iplists.firehol.org/files/cruzit_web_attacks.ipset",
        "description": "IPs of compromised machines scanning for vulnerabilities and DDOS attacks.",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[63:]
        for line in lines:
            self.analyze(line)

    def analyze(self, line):
        line = line.strip()

        ip = line

        context = {"source": self.name}

        try:
            obs = Ip.get_or_create(value=ip)
            obs.add_context(context)
            obs.add_source(self.name)
            obs.tag("cruzit")
        except ObservableValidationError as e:
            raise logging.error(e)
