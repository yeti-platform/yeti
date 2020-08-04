from __future__ import unicode_literals

import json
from datetime import datetime

import requests

from core.analytics import OneShotAnalytics
from core.config.config import yeti_config
from core.observables import Hostname, Ip, Url, Hash, Text


class VirustotalApi(object):
    """Base class for querying the VirusTotal API.
    This is the public API, so there is a limit for up to 3
    requests per minute.

    TODO: Register a redis key with the last query time and prevent
    limit rejection, as it could cause api key deactivation.
    """
    settings = {
        'virutotal_api_key': {
            'name': 'Virustotal API Key',
            'description': 'API Key provided by virustotal.com.'
        }
    }

    @staticmethod
    def fetch(api_key, endpoint):
        """
        :param observable: The extended observable klass
        :param api_key: The api key obtained from VirusTotal
        :param endpoint: endpoint VT API
        :return:  virustotal json response or None if error
        """
        try:
            response = None
            base_url = 'https://www.virustotal.com/api/v3'
            url = base_url + endpoint
            header = {
                'x-apikey': api_key
            }
            response = requests.get(
                url,
                headers=header,
                proxies=yeti_config.proxy)

            if response.ok:
                return response.json()
            else:
                return None
        except Exception as e:
            print('Exception while getting ip report {}'.format(e.message))
            return None

    @staticmethod
    def process_domain(domain, attributes):
        context = {
            'source': 'VirusTotal'
        }
        links = set()

        timestamp_creation = attributes['creation_date']
        context['first_seen'] = datetime.fromtimestamp(
            timestamp_creation).isoformat()
        context['whois'] = attributes['whois']
        if 'whois_date' in attributes:
            timestamp_whois_date = attributes['whois_date']
            context['whois_date'] = datetime.fromtimestamp(
                timestamp_creation).isoformat()
        if 'last_dns_records' in attributes:
            last_dns_records = attributes['last_dns_records']

            for rr in last_dns_records:
                related_obs = None
                if rr['type'] == 'A':
                    related_obs = Ip.get_or_create(value=rr['value'])
                elif rr['type'] == 'MX':
                    related_obs = Hostname.get_or_create(value=rr['value'])
                elif rr['type'] == 'SOA':
                    related_obs = Hostname.get_or_create(value=rr['value'])
                elif rr['type'] == 'NS':
                    related_obs = Hostname.get_or_create(value=rr['value'])
                if related_obs:
                    links.update(
                        related_obs.active_link_to(domain, rr['type'],
                                                   context['source']))

        if 'last_dns_records_date' in attributes:
            timestamp_lst_dns_record = attributes['last_dns_records_date']
            context['last_dns_records_date'] = datetime.fromtimestamp(
                timestamp_lst_dns_record).isoformat()
        if 'registrar' in attributes:
            context['registrar'] = attributes['registrar']

        tags = attributes['tags']
        if tags:
            domain.tag(tags)
        if 'popularity_ranks' in attributes:
            alexa_rank = attributes['popularity_ranks']

            if alexa_rank:
                context['alexa_rank'] = alexa_rank['Alexa']['rank']
                timestamp_rank = alexa_rank['Alexa']['timestamp']
                context['alexa_rank_date'] = datetime.fromtimestamp(
                    timestamp_creation).isoformat()

        if 'last_analysis_stats' in attributes:
            stats_analysis = attributes['last_analysis_stats']

            for k, v in stats_analysis.items():
                context[k] = v
        if 'last_https_certificate' and 'last_https_certificate_date' in attributes:
            context['last_https_certificate'] = attributes[
                'last_https_certificate']
            try:
                timestamp_https_cert = attributes['last_https_certificate_date']
                context['last_https_certificate_date'] = datetime.fromtimestamp(
                    timestamp_https_cert).isoformat()

            except TypeError or ValueError:
                pass

        domain.add_context(context)
        return links

    @staticmethod
    def process_file(file_vt, attributes):
        context = {
            'source': 'VirusTotal'
        }
        links = set()
        stat_files = attributes['last_analysis_stats']
        for k, v in stat_files.items():
            context[k] = v
        context['magic'] = attributes['magic']
        first_seen = attributes['first_submission_date']

        context['first_seen'] = datetime.fromtimestamp(
            first_seen).isoformat()

        last_seen = attributes['last_analysis_date']
        context['last_seen'] = datetime.fromtimestamp(last_seen).isoformat()
        context['names'] = ' '.join(n for n in
                                    attributes['names'])
        tags = attributes['tags']
        if attributes['last_analysis_results']:
            context['raw'] = attributes[
                'last_analysis_results']
        if tags:
            file_vt.tag(tags)
        observables = [
            (h, Hash.get_or_create(value=attributes[h]))
            for h in ('sha256', 'md5', 'sha1')
            if file_vt.value != attributes[h]]
        for h, obs in observables:
            obs.add_context(context)
            links.update(
                obs.active_link_to(file_vt, h, context['source']))

        file_vt.add_context(context)
        return links


class VTFileIPContacted(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT IP Contacted',
        'description': 'Perform a Virustotal query to contacted domains by a file.',
    }

    ACTS_ON = ['Hash']

    @staticmethod
    def analyze(observable, result):
        links = set()
        context = {
            'source': 'VirusTotal'
        }

        endpoint = '/files/%s/contacted_ips' % observable.value
        api_key = result.settings['virutotal_api_key']

        result = VirustotalApi.fetch(api_key, endpoint)
        if result:
            for data in result['data']:
                ip = Ip.get_or_create(value=data['id'])

                attributes = data['attributes']

                context['whois'] = attributes['whois']
                whois_timestamp = attributes['whois_date']
                whois_date = datetime.fromtimestamp(whois_timestamp).isoformat()
                context['whois_date'] = whois_date

                context['country'] = attributes['country']

                asn = Text.get_or_create(value=str(attributes['asn']))
                ip.active_link_to(asn, 'AS', 'Virustotal.com')

                context['as_owner'] = attributes['as_owner']
                context['last_https_certificate'] = json.dumps(attributes[
                                                                   'last_https_certificate'])

                stat_files = attributes['last_analysis_stats']

                for k, v in stat_files.items():
                    context[k] = v

                ip.add_context(context)
                links.update(ip.active_link_to(observable, 'contacted by',
                                               context['source']))
        return list(links)


class VTFileUrlContacted(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Urls Contacted',
        'description': 'Perform a Virustotal query to contacted domains by a file.',
    }

    ACTS_ON = ['Hash']

    @staticmethod
    def analyze(observable, result):
        links = set()
        context = {
            'source': 'VirusTotal'
        }

        endpoint = '/files/%s/contacted_urls' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)
        if result:
            for data in result['data']:
                attributes = data['attributes']

                timestamp_first_submit = attributes['first_submission_date']
                context['first_seen'] = datetime.fromtimestamp(
                    timestamp_first_submit).isoformat()

                url = Url.get_or_create(value=attributes['url'])
                links.update(url.active_link_to(observable, 'contact by',
                                                context['source']))
                context['last_http_response_code'] = str(
                    attributes['last_http_response_code'])
                context['last_http_response_content_length'] = str(
                    attributes['last_http_response_content_length'])

                timestamp_last_modif = attributes['last_modification_date']
                context['last_modification_date'] = datetime.fromtimestamp(
                    timestamp_last_modif).isoformat()

                timestamp_last_analysis = attributes['last_analysis_date']
                context['last_analysis_date'] = datetime.fromtimestamp(
                    timestamp_last_analysis).isoformat()

                stat_files = data['attributes']['last_analysis_stats']
                for k, v in stat_files.items():
                    context[k] = v
                tags = attributes['tags']
                if tags:
                    url.tag(tags)

                url.add_context(context)


class VTDomainContacted(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Domain Contacted',
        'description': 'Perform a Virustotal query to contacted domains by a file.',
    }

    ACTS_ON = ['Hash']

    @staticmethod
    def analyze(observable, result):
        links = set()
        context = {
            'source': 'VirusTotal'
        }

        endpoint = '/files/%s/contacted_domains' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)

        if result:
            for data in result['data']:
                hostname = Hostname.get_or_create(value=data['id'])
                context['first_seen'] = data['attributes']['creation_date']
                stat_files = data['attributes']['last_analysis_stats']
                context['registrar'] = data['attributes']['registrar']
                context['whois'] = data['attributes']['whois']
                for k, v in stat_files.items():
                    context[k] = v
                links.update(hostname.active_link_to(observable, 'contacted by',
                                                     context['source']))
                hostname.add_context(context)
        return links


class VTFileReport(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Hash Report',
        'description': 'Perform a Virustotal query to have a report.',
    }

    ACTS_ON = ['Hash']

    @staticmethod
    def analyze(observable, result):
        links = set()
        context = {
            'source': 'VirusTotal'
        }

        endpoint = '/files/%s' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)

        if result:
            links.update(VirustotalApi.process_file(observable, result['data'][
                'attributes']))
        return list(links)


class VTDomainReport(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Domain Report',
        'description': 'Perform a Virustotal query to have a report.',
    }

    ACTS_ON = ['Hostname']

    @staticmethod
    def analyze(observable, result):
        links = set()
        context = {
            'source': 'VirusTotal'
        }

        endpoint = '/domains/%s' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)

        if result:
            attributes = result['data']['attributes']
            links.update(VirustotalApi.process_domain(observable, attributes))
        return list(links)


class VTDomainResolution(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Domain Resolution',
        'description': 'Perform a Virustotal query to have subdomains.',
    }

    ACTS_ON = ['Hostname']

    @staticmethod
    def analyze(observable, result):
        links = set()
        context = {
            'source': 'VirusTotal PDNS'
        }

        endpoint = '/domains/%s/resolutions' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)

        if result:
            for data in result['data']:
                attribute = data['attributes']
                ip_address = attribute['ip_address']
                ip = Ip.get_or_create(value=ip_address)
                links.update(
                    ip.active_link_to(observable, 'PDNS', context['source']))
                timestamp_resolv = attribute['date']
                date_last_resolv = datetime.fromtimestamp(
                    timestamp_resolv).isoformat()
                context['date_last_resolution'] = 'ip: %s date: %s' % (
                    ip_address,
                    date_last_resolv)

                ip.add_context(
                    {'source': context['source'],
                     'date_last_resolution': 'domain: %s date: %s' % (
                         observable.value, date_last_resolv
                     )
                     }
                )
            if 'date_last_resolution' in context:
                observable.add_context(context)
        return list(links)


class VTSubdomains(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Subdomains',
        'description': 'Perform a Virustotal query to have subdomains.',
    }

    ACTS_ON = ['Hostname']

    @staticmethod
    def analyze(observable, result):
        links = set()
        endpoint = '/domains/%s/subdomains' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)

        if result:
            for data in result['data']:
                context = {
                    'source': 'VirusTotal'
                }
                attributes = data['attributes']
                sub_domain = Hostname.get_or_create(value=data['id'])
                links.update(
                    VirustotalApi.process_domain(sub_domain, attributes))
                links.update(sub_domain.active_link_to(observable, 'subdomain',
                                                       context['source']))
        return list(links)


class VTDomainComFile(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Com files domain',
        'description': 'Perform a Virustotal query to have subdomains.',
    }

    ACTS_ON = ['Hostname']

    @staticmethod
    def analyze(observable, result):
        links = set()
        endpoint = '/domains/%s/communicating_files' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)
        for data in result['data']:
            attributes = data['attributes']
            file_vt = Hash.get_or_create(value=data['id'])
            links.update(file_vt.active_link_to(observable, 'communicating',
                                                'Virustotal'))
            links.update(VirustotalApi.process_file(file_vt, attributes))

        return list(links)


class VTDomainReferrerFile(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT Referrer files domain',
        'description': 'Perform a Virustotal query to have subdomains.',
    }

    ACTS_ON = ['Hostname']

    @staticmethod
    def analyze(observable, result):
        links = set()
        endpoint = '/domains/%s/referrer_files' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)
        for data in result['data']:
            attributes = data['attributes']
            file_vt = Hash.get_or_create(value=data['id'])
            links.update(file_vt.active_link_to(observable, 'Referrer File',
                                                'Virustotal'))
            links.update(VirustotalApi.process_file(file_vt, attributes))

        return list(links)


class VTIPResolution(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT IP Resolution',
        'description': 'Perform a Virustotal query to have subdomains.',
    }

    ACTS_ON = ['Ip']

    @staticmethod
    def analyze(observable, result):
        links = set()

        endpoint = '/ip_addresses/%s/resolutions' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)

        if result:
            for data in result['data']:
                context = {
                    'source': 'VirusTotal PDNS'
                }
                attributes = data['attributes']
                hostname = Hostname.get_or_create(value=attributes['host_name'])
                if 'date' in attributes:
                    timestamp_date = attributes['date']
                    date_last_resolv = datetime.fromtimestamp(
                        timestamp_date).isoformat()
                    context['date_last_resolution'] = 'domain: %s date: %s' % (
                        hostname.value,
                        date_last_resolv
                    )
                    hostname.add_context(
                        {'source': context['source'],
                         'date_last_resolution': 'ip: %s date: %s' % (
                             observable.value,
                             date_last_resolv)})
                links.update(hostname.active_link_to(observable, 'resolved',
                                                     context['source']))

        return list(links)


class VTIPComFile(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT IP Com files',
        'description': 'Perform a Virustotal query to have subdomains.',
    }

    ACTS_ON = ['Ip']

    @staticmethod
    def analyze(observable, result):
        links = set()
        endpoint = '/ip_addresses/%s/communicating_files' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)

        for data in result['data']:
            attributes = data['attributes']
            file_vt = Hash.get_or_create(value=data['id'])
            links.update(file_vt.active_link_to(observable, 'communicating',
                                                'Virustotal'))
            links.update(VirustotalApi.process_file(file_vt, attributes))

        return list(links)


class VTIPReferrerFile(OneShotAnalytics, VirustotalApi):
    default_values = {
        'group': 'Virustotal',
        'name': 'VT IP Referrer files',
        'description': 'Perform a Virustotal query to have subdomains.',
    }

    ACTS_ON = ['Ip']

    @staticmethod
    def analyze(observable, result):
        links = set()
        endpoint = '/ip_addresses/%s/referrer_files' % observable.value
        api_key = result.settings['virutotal_api_key']
        result = VirustotalApi.fetch(api_key, endpoint)
        for data in result['data']:
            attributes = data['attributes']
            file_vt = Hash.get_or_create(value=data['id'])
            links.update(file_vt.active_link_to(observable, 'Referrer File',
                                                'Virustotal'))
            links.update(VirustotalApi.process_file(file_vt, attributes))

        return list(links)
