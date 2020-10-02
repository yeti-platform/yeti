import logging
from datetime import timedelta

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url


class Obtemoslab(Feed):
    default_values = {
        "frequency": timedelta(hours=24),
        "name": "Obtemoslab",
        "source": "http://tracker.0btemoslab.com/tracker/Malware.txt",
        "description": "List of payload locations",
    }

    def update(self):
        resp = self._make_request(sort=False)
        lines = resp.content.decode("utf-8").split("\r\n")[4:-1]
        for url in lines:
            self.analyze(url.strip())

    def analyze(self, url):

        try:
            url_data = Url.get_or_create(value=url)
            url_data.normalize()
            url_data.tags.append(["payload_delivery"])
            url_data.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)
