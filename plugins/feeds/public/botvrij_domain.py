import logging
from datetime import timedelta, datetime
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Hostname


class BotvrijDomain(Feed):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijDomain",
        "source": "https://www.botvrij.eu/data/ioclist.domain",
        "description": "Detect possible outbound malicious activity.",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[6:-1]
        for line in lines:
            self.analyze(line)

    def analyze(self, item):
        hostn, descr = item.split(" # domain - ")

        context = {
            "source": self.name,
            "description": descr,
            "date_added": datetime.utcnow(),
        }

        try:
            obs = Hostname.get_or_create(value=hostn)
            obs.add_context(context, dedup_list=["date_added"])
            obs.add_source(self.name)
            obs.tag("botvrij")
        except ObservableValidationError as e:
            logging.error(e)
