import requests
import logging
from datetime import datetime, timedelta
from core.observables import Url
from core.feed import Feed
from core.errors import ObservableValidationError
from core.config.config import yeti_config

class Obtemoslab(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "Obtemoslab",
        "source" : "http://tracker.0btemoslab.com/tracker/Malware.txt",
        "description": "List of payload locations",
    }

    def update(self):
        resp = requests.get(self.source, proxies=yeti_config.proxy)
        if resp.ok and resp.content:
            lines = resp.content.split("\r\n")[4:-1]
            for url in lines:
                self.analyze(url)

    def analyze(self, url):

        context = {}
        context['date_added'] = datetime.now()
        context['source'] = self.name

        try:
            url_data = Url.get_or_create(value=url)
            url_data.normalize()
            url_data.add_context(context)
            url_data.add_source("feed")
        except ObservableValidationError as e:
            logging.error(e)
