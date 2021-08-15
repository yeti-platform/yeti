import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class ThreatviewC2_IP(Feed):

    default_values = {
        "frequency": timedelta(hours=13),
        "name": "ThreatviewC2_IP",
        "source": "https://threatview.io/Downloads/High-Confidence-CobaltstrikeC2_IP_feed.txt",
        "description": "Infrastructure hosting Command & Control Servers found during Proactive Hunt by Threatview.io",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[2:]
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
            obs.tag("threatview")
            obs.tag("cobalt_strike")
            obs.tag("c2")
        except ObservableValidationError as e:
            raise logging.error(e)
