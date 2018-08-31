from datetime import timedelta

from core import Feed
from core.config.config import yeti_config


class OTXAlienvault(Feed):
    default_values = {
        "frequency": timedelta(minutes=5),
        "name": "OTXAlienvault",
        "source": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "description": "Feed of OTX by Alienvault"

    }

    def update(self):
        otx_key = yeti_config.get('otx', 'key')

        headers = {'X-OTX-API-KEY': otx_key}

        for i in range(1, 6):
            item = self.update_json(headers=headers, params={'page': i})
            print(type(item))
            print(item)
            self.analyze(item)

    def analyze(self, item):
        pass
