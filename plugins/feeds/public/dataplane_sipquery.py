import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class DataplaneSIPQuery(Feed):

    default_values = {
        "frequency": timedelta(hours=2),
        "name": "DataplaneSIPQuery",
        "source": "https://dataplane.org/sipquery.txt",
        "description": "Entries below are records of source IP addresses that have been identified as sending SIP OPTIONS queries.",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[64:-5]
        for url in lines:
            self.analyze(url.strip())

    def analyze(self, line):
        val = line.split("|")[2].strip()

        context = {
            "source": self.name,
        }

        try:
            obs = Ip.get_or_create(value=val)
            obs.add_context(context)
            obs.add_source(self.name)
            obs.tag("dataplane")
            obs.tag("sip")
        except ObservableValidationError as e:
            raise logging.error(e)
