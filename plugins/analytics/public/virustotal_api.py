from __future__ import unicode_literals

import json

import requests

from core.analytics import OneShotAnalytics
from core.config.config import yeti_config
from core.entities import Company
from core.observables import Hostname, Ip, Url, Hash


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
    def fetch(observable, api_key):
        """
        :param observable: The extended observable klass
        :param api_key: The api key obtained from VirusTotal
        :return:  virustotal json response or None if error
        """
        try:
            response = None
            if isinstance(observable, Hostname):
                params = {'resource': observable.value, 'apikey': api_key}
                response = requests.get(
                    'https://www.virustotal.com/vtapi/v2/url/report',
                    params,
                    proxies=yeti_config.proxy)

            elif isinstance(observable, Ip):
                params = {'ip': observable.value, 'apikey': api_key}
                response = requests.get(
                    'https://www.virustotal.com/vtapi/v2/ip-address/report',
                    params,
                    proxies=yeti_config.proxy)
            elif isinstance(observable, Hash):
                params = {'resource': observable.value, 'apikey': api_key}
                response = requests.get(
                    'https://www.virustotal.com/vtapi/v2/file/report',
                    params,
                    proxies=yeti_config.proxy)
            if response.ok:
                return response.json()
            else:
                return None
        except Exception as e:
            print 'Exception while getting ip report {}'.format(e.message)
            return None


class VirusTotalQuery(OneShotAnalytics, VirustotalApi):
    default_values = {
        'name': 'Virustotal',
        'description': 'Perform a Virustotal query.',
    }

    ACTS_ON = ['Ip', 'Hostname', 'Hash']

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = VirustotalApi.fetch(
            observable, results.settings['virutotal_api_key'])
        json_string = json.dumps(
            json_result, sort_keys=True, indent=4, separators=(',', ': '))
        results.update(raw=json_string)

        result = dict([('raw', json_string), ('source', 'virustotal_query')])

        if json_result['response_code'] != 1:

            result['scan_date'] = None
            result['positives'] = 0
            result['total'] = 0
            result['permalink'] = None

            observable.add_context(result)
            return

        if isinstance(observable, Ip):

            # Parse results for ip
            if json_result.get('as_owner'):
                result['owner'] = json_result['as_owner']
                o_isp = Company.get_or_create(name=json_result['as_owner'])
                links.update(
                    observable.active_link_to(
                        o_isp, 'hosting', 'virustotal_query'))

            if json_result.get('detected_urls'):
                result['detected_urls'] = json_result['detected_urls']
                for detected_url in json_result['detected_urls']:
                    o_url = Url.get_or_create(value=detected_url['url'])
                    links.update(
                        o_url.active_link_to(
                            o_url, 'hostname', 'virustotal_query'))

            if json_result.get('permalink'):
                result['permalink'] = json_result['permalink']

        elif isinstance(observable, Hostname):

            if json_result.get('permalink'):
                result['permalink'] = json_result['permalink']

            result['positives'] = json_result.get('positives', 0)

            if json_result.get('total'):
                result['total'] = json_result['total']

        elif isinstance(observable, Hash):

            result['positives'] = json_result.get('positives', 0)

            if 'permalink' in json_result:
                result['permalink'] = json_result['permalink']

            if 'total' in json_result:
                result['total'] = json_result['total']

            hashes = {
                'md5': json_result['md5'],
                'sha1': json_result['sha1'],
                'sha256': json_result['sha256']
            }
            create_hashes = [
                (k, v) for k, v in hashes.items() if v != observable.value
            ]

            for k, v in create_hashes:
                new_hash = Hash.get_or_create(value=v)
                new_hash.tag(observable.get_tags())
                links.update(
                    new_hash.active_link_to(observable, k,
                                            'virustotal_query'))

            result['scan_date'] = json_result['scan_date']

        observable.add_context(result)
        return list(links)
