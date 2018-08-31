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
            self.analyze(item)

    def analyze(self, item):
        md5_indicators = OTXAlienvault.__choose_type_indic(item['indicators'],
                                                           'FileHash-MD5')

        sha256_indic = OTXAlienvault.__choose_type_indic(item['indicators'],
                                                         'FileHash-SHA256')

        sha1_indic = OTXAlienvault.__choose_type_indic(item['indicators'],
                                                       'FileHash-SHA1')

        sha256_indic = OTXAlienvault.__choose_type_indic(item['indicators'],
                                                         'FileHash-SHA256')

        urls = OTXAlienvault.__choose_type_indic(item['indicators'], 'URL')

        domains = OTXAlienvault.__choose_type_indic(item['indicators'],
                                                    'domain')

        hostnames = OTXAlienvault.__choose_type_indic(item['indicators'],
                                                      'domains')

        pass

    @staticmethod
    def __choose_type_indic(indicators, type_indic):
        return list(filter(lambda x: x['type'] == type_indic, indicators))
