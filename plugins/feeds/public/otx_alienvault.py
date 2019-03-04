import logging
from datetime import datetime
from datetime import timedelta

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
            'hostname': (Hostname, Observable),
            'domain': (Hostname, Observable),
            'FileHash-MD5': (Hash, Observable),
            'FileHash-SHA256': (Hash, Observable),
            'FileHash-SHA1': (Hash, Observable),
            'URL': (Url, Observable),
            'YARA': (Yara, Indicator),
            'CVE': (Exploit, Entity),

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

        observables = {}

        context = dict(source=self.name)
        context['references'] = '\r\n'.join(item['references'])
        context['description'] = item['description']
        context['link'] = 'https://otx.alienvault.com/pulse/%s' % item['id']

        tags = item['tags']
        entities = []

        for indicator in item['indicators']:
            type_ind = self.refs.get(indicator['type'])
            if type_ind:
                context['title'] = indicator['title']
                context['infos'] = indicator['description']
                context['created'] = datetime.strptime(indicator['created'],
                                                       '%Y-%m-%dT%H:%M:%S')
                if type_ind[1] == Observable:
                    try:
                        obs = type_ind[0].get_or_create(
                            value=indicator['indicator'])
                        obs.tag(tags)
                        obs.add_context(context)
                        obs.add_source('feed')

                    except ObservableValidationError as e:
                        logging.error(e)
                elif type_ind[1] == Entity:
                    ent = type_ind[0].get_or_create(name=indicator['indicator'])
                    entities.append(ent)
                elif type_ind[1] == Indicator:
                    if type_ind == Yara:
                        ent = type_ind[0].get_or_create(name='YARA_%s' %
                                                             indicator[
                                                                 'indicator'])
                        ent.pattern(indicator['content'])

                else:
                    logging.error('type of indicators is unknown %s',
                                  indicator['type'])
