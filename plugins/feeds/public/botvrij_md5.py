import logging
from datetime import timedelta
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
        for url in lines:
            self.analyze(url.strip())

    def analyze(self, line):
        val, descr = line.split(" # md5 - ")

        context = {"source": self.name, "description": descr}

        try:
            obs = Hash.get_or_create(value=val)
            obs.add_context(context)
            obs.add_source(self.name)
            obs.tag("botvrij")
        except ObservableValidationError as e:
            raise logging.error(e)
