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
                last_dns_records = data['attributes']['last_dns_records']

                for rr in last_dns_records:
                    ip = Ip.get_or_create(value=rr['value'])
                    ip.active_link_to(hostname, rr['type'], 'VT PDNS')
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
            stat_files = result['data']['attributes']['last_analysis_stats']
            for k, v in stat_files.items():
                context[k] = v
            context['magic'] = result['data']['attributes']['magic']
            first_seen = result['data']['attributes']['first_submission_date']

            context['first_seen'] = datetime.fromtimestamp(
                first_seen).isoformat()

            last_seen = result['data']['attributes']['last_analysis_date']
            context['last_seen'] = datetime.fromtimestamp(last_seen).isoformat()
            context['names'] = ' '.join(n for n in
                                        result['data']['attributes']['names'])
            tags = result['data']['attributes']['tags']
            if result['data']['attributes']['last_analysis_results']:
                context['analysis result'] = result['data']['attributes'][
                    'last_analysis_results']
            if tags:
                observable.tag(tags)
            observables = [
                (h, Hash.get_or_create(value=result['data']['attributes'][h]))
                for h in ('sha256', 'md5', 'sha1')
                if observable.value != result['data']['attributes'][h]]
            for h, obs in observables:
                obs.add_context(context)
                links.update(
                    obs.active_link_to(observable, h, context['source']))

        observable.add_context(context)
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
            timestamp_creation = attributes['creation_date']
            context['first_seen'] = datetime.fromtimestamp(
                timestamp_creation).isoformat()
            context['whois'] = attributes['whois']
            timestamp_whois_date = attributes['whois_date']
            context['whois_date'] = datetime.fromtimestamp(
                timestamp_creation).isoformat()
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
                        related_obs.active_link_to(observable, rr['type'],
                                                   context['source']))

            timestamp_lst_dns_record = attributes['last_dns_records_date']
            context['last_dns_records_date'] = datetime.fromtimestamp(
                timestamp_lst_dns_record).isoformat()
            context['registrar'] = attributes['registrar']

            tags = attributes['tags']
            if tags:
                observable.tag(tags)
            alexa_rank = attributes['popularity_ranks']

            if alexa_rank:
                context['alexa_rank'] = alexa_rank['Alexa']['rank']
                timestamp_rank = alexa_rank['Alexa']['timestamp']
                context['alexa_rank_date'] = datetime.fromtimestamp(
                    timestamp_creation).isoformat()

            stats_analysis = attributes['last_analysis_stats']

            for k, v in stats_analysis.items():
                context[k] = v

            context['last_https_certificate'] = attributes[
                'last_https_certificate']

            timestamp_https_cert = attributes['last_https_certificate_date']
            context['last_https_certificate_date'] = datetime.fromtimestamp(
                timestamp_https_cert).isoformat()

            context['last_https_certificate'] = attributes[
                'last_https_certificate']

            observable.add_context(context)
        return list(links)
