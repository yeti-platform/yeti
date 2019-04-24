import logging
from datetime import datetime, timedelta
from core.observables import Hash
from core.feed import Feed
from core.errors import ObservableValidationError

class CertPaIt(Feed):

    default_values = {
        "frequency": timedelta(minutes=30),
        "name": "CertPaIT",
        "source" : "https://infosec.cert-pa.it/analyze/submission.rss",
        "description": "This feed contains data from infosec.cert-pa.it",
    }

    def update(self):
        for item in self.update_xml('item', ["title", "link"]):
            self.analyze(item)

    def analyze(self, item):
        md5 = item['title'].replace("MD5: ", "")
        context = {}
        context['date_added'] = datetime.now()
        context['source'] = self.name
        context['url'] = item['link']

        try:
            if md5:
                hash_data = Hash.get_or_create(value=md5)
                if hash_data.new is True or self.name not in hash_data.sources:
                    hash_data.add_context(context)
                    hash_data.add_source(self.name)

        except ObservableValidationError as e:
            logging.error(e)
