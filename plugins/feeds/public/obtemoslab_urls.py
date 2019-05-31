import logging
from datetime import timedelta

from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError

class Obtemoslab(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "Obtemoslab",
        "source": "http://tracker.0btemoslab.com/tracker/Malware.txt",
        "description": "List of payload locations",
    }

    def update(self):
        resp = self._make_request()
        lines = resp.content.split("\r\n")[4:-1]
        for url in lines:
            self.analyze(url)

    def analyze(self, url):

        try:
            url_data = Url.get_or_create(value=url)
            url_data.normalize()
            url_data.tags(["payload_delivery"])
            url_data.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)
