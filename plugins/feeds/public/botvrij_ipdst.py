import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class BotvrijIPDst(Feed):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijIPDst",
        "source": "https://www.botvrij.eu/data/ioclist.ip-dst",
        "description": "Detect possible outbound malicious activity.",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[6:-1]
        for url in lines:
            self.analyze(url.strip())

    def analyze(self, line):
        ip, descr = line.split(" # ip-dst - ")

        context = {"source": self.name, "description": descr}

        try:
            obs = Ip.get_or_create(value=ip)
            obs.add_context(context)
            obs.add_source(self.name)
            obs.tag("botvrij")
        except ObservableValidationError as e:
            raise logging.error(e)
