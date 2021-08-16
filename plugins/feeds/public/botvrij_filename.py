import logging
from datetime import timedelta
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import File


class BotvrijFilename(Feed):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijFilename",
        "source": "https://www.botvrij.eu/data/ioclist.filename",
        "description": "IOClist - filename",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\n")[6:-1]

        for line in lines:
            self.analyze(line.strip())

    def analyze(self, line):
        hostn, descr = line.split(" # filename - ")

        context = {"source": self.name, "description": descr}

        try:
            obs = File.get_or_create(value=hostn)
            obs.add_context(context)
            obs.add_source(self.name)
            obs.tag("botvrij")
        except ObservableValidationError as e:
            raise logging.error(e)
