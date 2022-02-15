import logging
from datetime import timedelta, datetime
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Hash


class BotvrijMD5(Feed):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijMD5",
        "source": "https://www.botvrij.eu/data/ioclist.md5",
        "description": "File hashes that can be used when doing incident response.",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[6:-1]

        for line in lines:
            self.analyze(line.strip())

    def analyze(self, item):
        val, descr = item.split(" # md5 - ")

        context = {
            "source": self.name,
            "description": descr,
            "date_added": datetime.utcnow(),
        }

        try:
            obs = Hash.get_or_create(value=val)
            obs.add_context(context, dedup_list=["date_added"])
            obs.add_source(self.name)
            obs.tag("botvrij")
        except ObservableValidationError as e:
            logging.error(e)
