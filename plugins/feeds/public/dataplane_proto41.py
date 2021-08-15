import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class DataplaneProto41(Feed):

    default_values = {
        "frequency": timedelta(hours=2),
        "name": "DataplaneProto41",
        "source": "https://dataplane.org/proto41.txt",
        "description": "Entries below are records of source IP addresses that have been identified as an open IPv4 protocol 41 relay (i.e. IPv6 over IPv4).",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[71:-5]
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
        except ObservableValidationError as e:
            raise logging.error(e)
