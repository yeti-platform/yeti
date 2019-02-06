import logging
from datetime import timedelta
from urlparse import urlparse

from core import Feed
from core.config.config import yeti_config
from core.entities import Exploit
from core.observables import Hash, Hostname, Url


class OTXAlienvault(Feed):
    default_values = {
        "frequency": timedelta(days=1),
        "name": "OTXAlienvault",
        "source": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "description": "Feed of OTX by Alienvault"

    }

    def update(self):
        otx_key = yeti_config.get('otx', 'key')

        number_page = yeti_config.get('otx', 'pages')

        assert otx_key and number_page

        headers = {'X-OTX-API-KEY': otx_key}

        for i in range(1, int(number_page)):
            items = self.update_json(headers=headers, params={'page': i})
            for item in items['results']:
                self.analyze(item)

    def analyze(self, item):

        observables = {}

        context = dict(source=self.name)

        OTXAlienvault.__create_list_observables(
            Hostname,
            'hostname',
            item['indicators'],
            observables,
            'hostnames')

        OTXAlienvault.__create_list_observables(
            Url,
            'URL',
            item['indicators'],
            observables,
            'urls')

        OTXAlienvault.__create_list_observables(
            Hostname,
            'domain',
            item['indicators'],
            observables,
            'domains')

        OTXAlienvault.__create_list_exploit(
            Exploit,
            'CVE',
            item['indicators'],
            observables,
            'exploits')

        OTXAlienvault.__create_list_observables(
            Hash,
            'FileHash-SHA256',
            item['indicators'],
            observables,
            'sha256')

        OTXAlienvault.__create_list_observables(
            Hash,
            'FileHash-MD5',
            item['indicators'],
            observables,
            'md5')

        OTXAlienvault.__create_list_observables(
            Hash,
            'FileHash-SHA1',
            item['indicators'],
            observables,
            'sha1')

        tags = item['tags']

        context['references'] = '\r\n'.join(item['references'])
        context['description'] = item['description']
        context['link'] = 'https://otx.alienvault.com/pulse/%s' % item['id']

        OTXAlienvault.__add_contex(context, observables)
        OTXAlienvault.__add_source(observables)
        if tags:
            OTXAlienvault.__add_tags(tags, observables)

        if observables.get('sha256'):
            self.__create_link_hashes_and_network_indic(
                observables['sha256'],
                observables['urls'])
            self.__create_link_hashes_and_network_indic(
                observables['sha256'],
                observables['domains'])
            self.__create_link_hashes_and_network_indic(
                observables['sha256'],
                observables['hostnames'])

        if observables.get('sha1'):
            self.__create_link_hashes_and_network_indic(
                observables['sha1'],
                observables['urls'])

            self.__create_link_hashes_and_network_indic(
                observables['sha1'],
                observables['domains'])

            self.__create_link_hashes_and_network_indic(
                observables['sha1'],
                observables['hostnames'])

        if observables.get('md5'):
            self.__create_link_hashes_and_network_indic(
                observables['md5'],
                observables['urls'])

            self.__create_link_hashes_and_network_indic(
                observables['md5'],
                observables['domains'])

            self.__create_link_hashes_and_network_indic(
                observables['md5'],
                observables['hostnames'])

        if observables.get('hostnames') or observables.get('domains'):
            self.__create_links_url_domains_hostnames(
                observables['domains'],
                observables['hostnames'],
                observables['urls'])

    def __create_links_url_domains_hostnames(self, domains_obs, hostnames_obs,
                                             urls_obs):
        for url, ind in urls_obs.items():
            if domains_obs:
                self.__search_link_between_url_and_hostames(url,
                                                            ind,
                                                            domains_obs)
            if hostnames_obs:
                self.__search_link_between_url_and_hostames(url,
                                                            ind,
                                                            hostnames_obs)

    def __search_link_between_url_and_hostames(self, url, ind, hostnames):
        r = urlparse(url)
        if r.netloc in list(hostnames.values()):
            hostnames[r.netloc].activelink(ind, 'domain', self.name)
        else:
            for domain, obs in hostnames.items():
                if domain in url:
                    obs.activelink(ind, 'domain ', self.name)

    def __create_link_hashes_and_network_indic(self, hashes, network_indic):

        for h in hashes.values():
            for n in network_indic.values():
                if isinstance(n, Url):
                    h.active_link_to(n, 'url', self.source)
                if isinstance(n, Hostname):
                    h.active_link_to(n, 'C2', self.source)
                logging.info('join %s %s' % (n.value, h.value))

    @staticmethod
    def __create_list_exploit(obj, type_indic, indicators, observables,
                              type_obs):

        OTXAlienvault.__filtering_by_entities(obj, type_indic, indicators,
                                              observables, type_obs)
    @staticmethod
    def __create_list_observables(obj, type_indic, indicators, observables,
                                  type_obs):
        OTXAlienvault.__filtering_by_entities(obj, type_indic, indicators,
                                              observables, type_obs)

    @staticmethod
    def __filtering_by_entities(obj, type_indic, indicators, observables,
                                type_obs):
        list_value = list(filter(lambda x: x['type'] == type_indic, indicators))

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
