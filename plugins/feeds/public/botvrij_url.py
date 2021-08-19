import logging
from datetime import timedelta,datetime
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url


class BotvrijUrl(Feed):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijUrl",
        "source": "https://www.botvrij.eu/data/ioclist.url",
        "description": "Detect possible outbound malicious activity.",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[6:-1]

        for line in lines:
            self.analyze(line.strip())

    def analyze(self, line):
        url, descr = line.split(" # url - ")

        context = {"source": self.name, "description": descr , "date_added": datetime.utcnow()}

        try:
            obs = Url.get_or_create(value=url)
            obs.add_context(context, dedup_list=["date_added"])
            obs.add_source(self.name)
            obs.tag("botvrij")
        except ObservableValidationError as e:
            logging.error(e)
