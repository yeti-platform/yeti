import logging
from datetime import datetime, timedelta

from core import Feed
from core.config.config import yeti_config
from core.entities import Exploit, Entity
from core.errors import ObservableValidationError
from core.indicators import Yara, Indicator
from core.observables import Hash, Hostname, Url, Observable


class OTXAlienvault(Feed):
    default_values = {
        "frequency": timedelta(days=1),
        "name": "OTXAlienvault",
        "source": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "description": "Feed of OTX by Alienvault"

    }

    def __init__(self, *args, **kwargs):
        self.refs = {
            'hostname': Hostname,
            'domain': Hostname,
            'FileHash-MD5': Hash,
            'FileHash-SHA256': Hash,
            'FileHash-SHA1': Hash,
            'URL': Url,
            'YARA': Yara,
            'CVE': Exploit

        }
        super(OTXAlienvault, self).__init__(*args, **kwargs)

    def update(self):
        otx_key = yeti_config.get('otx', 'key')

        number_page = yeti_config.get('otx', 'pages')

        assert otx_key and number_page

        headers = {'X-OTX-API-KEY': otx_key}

        for i in range(1, int(number_page)):
            items = self.update_json(headers=headers, params={'page': i})
            if 'results' in items:
                for item in items['results']:
                    self.analyze(item)

    def analyze(self, item):

        context = dict(source=self.name)
        context['references'] = '\r\n'.join(item['references'])
        context['description'] = item['description']
        context['link'] = 'https://otx.alienvault.com/pulse/%s' % item['id']

        tags = item['tags']

        for indicator in item['indicators']:

            type_ind = self.refs.get(indicator['type'])
            if not type_ind:
                continue

            context['title'] = indicator['title']
            context['infos'] = indicator['description']
            context['created'] = datetime.strptime(indicator['created'],
                                                   '%Y-%m-%dT%H:%M:%S')
            if issubclass(type_ind, Observable):
                try:
                    obs = type_ind.get_or_create(
                        value=indicator['indicator'])
                    obs.tag(tags)
                    obs.add_context(context)
                    obs.add_source('feed')

                except ObservableValidationError as e:
                    logging.error(e)

            elif issubclass(type_ind, Entity):

                type_ind.get_or_create(name=indicator['indicator'])

            elif issubclass(type_ind, Indicator):
                if type_ind == Yara:
                    ent = type_ind.get_or_create(name='YARA_%s' %
                                                      indicator[
                                                          'indicator'])
                    ent.pattern(indicator['content'])

            else:
                logging.error('type of indicators is unknown %s',
                              indicator['type'])
