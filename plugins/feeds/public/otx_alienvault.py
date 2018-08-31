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
            item = self.update_json(headers=headers, params={'page': i})
            self.analyze(item)

    def analyze(self, item):

        context = dict(source=self.name)

        md5_indic = OTXAlienvault.__choose_type_indic(item['indicators'],
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

        exploits = OTXAlienvault.__choose_type_indic(item['indicatore'], 'CVE')

        hostnames_obs = {
        h['indicator']: Hostname.get_or_create(value=h['indicator']) for h in
        hostnames}
        urls_obs = {url['indicator']: Url.get_or_create(value=url['indicator'])
                    for url in urls}
        domains_obs = {
        domain['indicator']: Hostname.get_or_create(value=domain['indicator'])
        for domain in domains}

        cve_obs = [Exploit.get_or_create(value=ex['indicator']) for ex in
                   exploits]

        tags = item['tags']

        context['links'] = item['references']

        sh256_obs = [Hash.get_or_create(value=sha256_f['indicator']) for
                     sha256_f in sha256_indic]
        md5_obs = [Hash.get_or_create(value=md5_f['indicator']) for md5_f in
                   md5_indic]
        sha1 = [Hash.get_or_create(value=sha1_f['indicator']) for sha1_f in
                sha1_indic]

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
                    obs.activelink(ind, 'domains', self.name)

    @staticmethod
    def __add_contex(context, obsevables):
        for o in obsevables:
            o.add_context(context)

    @staticmethod
    def __add_source(observables):
        for o in observables:
            o.add_source('feed')

    @staticmethod
    def __add_tags(tags, observables):
        for o in observables:
            o.tag(tags)
    @staticmethod
    def __choose_type_indic(indicators, type_indic):
        return list(filter(lambda x: x['type'] == type_indic, indicators))
