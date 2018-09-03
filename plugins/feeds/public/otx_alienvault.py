from datetime import timedelta
from urlparse import urlparse

from core import Feed
from core.config.config import yeti_config
from core.entities import Exploit
from core.observables import Hash, Hostname, Url


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
            items = self.update_json(headers=headers, params={'page': i})
            for item in items['results']:
                self.analyze(item)

    def analyze(self, item):

        observables = {}

        context = dict(source=self.name)

        OTXAlienvault.__create_list_observables(Hostname,
                                                'hostname',
                                                item[
                                                    'indicators']
                                                , observables
                                                , 'hostnames')

        OTXAlienvault.__create_list_observables(Url, 'URL', item['indicators'],
                                                observables, 'urls')

        OTXAlienvault.__create_list_observables(Hostname, 'domain',
                                                item['indicators']
                                                , observables,
                                                'domains')

        OTXAlienvault.__create_list_observables(Exploit, 'CVE',
                                                item['indicators'], observables,
                                                'exploits')

        OTXAlienvault.__create_list_observables(Hash,
                                                'FileHash-SHA256',
                                                item['indicators'],
                                                observables, 'sha256')

        OTXAlienvault.__create_list_observables(Hash, 'FileHash-MD5',
                                                item['indicators'], observables,
                                                'md5')

        OTXAlienvault.__create_list_observables(Hash, 'FileHash-SHA1'
                                                , item['indicators'],
                                                observables, 'sha1')

        tags = item['tags']

        context['links'] = item['references']

        OTXAlienvault.__add_contex(context, observables)
        OTXAlienvault.__add_source(observables)
        if tags:
            OTXAlienvault.__add_tags(tags, observables)


    def __create_links_url_domains_hostnames(self, domains_obs, hostnames_obs,
                                             urls_obs):
        for url, ind in urls_obs.items():
            self.__search_link_between_url_and_hostames(url, ind,
                                                        domains_obs)
            self.__search_link_between_url_and_hostames(url, ind,
                                                        hostnames_obs)

    def __search_link_between_url_and_hostames(self, url, ind, hostnames):
        r = urlparse(url)
        if r.netloc in list(hostnames.values()):
            hostnames[r.netloc].activelink(ind, 'domain', self.name)
        else:
            for domain, obs in hostnames.items():
                if domain in url:
                    obs.activelink(ind, 'domain ', self.name)

    @staticmethod
    def __create_list_observables(obj, type_indic, indicators, observables,
                                  type_obs):
        list_value = list(filter(lambda x: x['type'] == type_indic, indicators))

        if obj == Exploit:
            observables[type_obs] = {ind['indicator']: obj.get_or_create(name=
                                                                         ind[
                                                                             'indicator'])
                                     for ind in list_value}
        else:
            observables[type_obs] = {ind['indicator']: obj.get_or_create(value=
                                                                         ind[
                                                                             'indicator'])
                                     for ind in list_value}

    @staticmethod
    def __add_contex(context, observables):
        for obs in observables.values():
            for o in obs.values():
                if not isinstance(o, Exploit):
                    o.add_context(context)

    @staticmethod
    def __add_source(observables):
        for obs in observables.values():
            for o in obs.values():
                if not isinstance(o, Exploit):
                    o.add_source('feed')

    @staticmethod
    def __add_tags(tags, observables):
        for obs in observables.values():
            for o in obs.values():
                if not isinstance(o, Exploit):
                    o.tag(tags)
