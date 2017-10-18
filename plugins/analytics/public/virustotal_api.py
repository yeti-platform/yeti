from core.analytics import OneShotAnalytics
from core.observables import Hostname, Ip, Url
from core.entities import Company
import requests
import json


class VirustotalApi(object):
    """
    Base class for querying the VirusTotal API.
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
                params = dict()
                params['resource'] = observable.value
                params['apikey'] = api_key
                # response = urllib.urlopen()
                response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params)

            elif isinstance(observable, Ip):
                params = dict()
                params['ip'] = observable.value
                params['apikey'] = api_key
                response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params)

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

    ACTS_ON = ['Ip', 'Hostname']

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = VirustotalApi.fetch(observable, results.settings['virutotal_api_key'])
        results.update(raw=json.dumps(json_result, sort_keys=True, indent=4, separators=(',', ': ')))
        result = dict()
        result['raw'] = json.dumps(json_result, sort_keys=True, indent=4, separators=(',', ': '))

        if isinstance(observable, Ip):
            # Parse results for ip
            if json_result.get('as_owner'):
                result['Owner'] = json_result['as_owner']
                o_isp = Company.get_or_create(name=json_result['as_owner'])
                links.update(observable.active_link_to(o_isp, 'hosting', 'virustotal_query'))

            if json_result.get('detected_urls'):
                result['detected_urls'] = json_result['detected_urls']
                for detected_url in json_result['detected_urls']:
                    o_url = Url.get_or_create(value=detected_url['url'])
                    links.update(o_url.active_link_to(o_url, 'hostname', 'virustotal_query'))

        elif isinstance(observable, Hostname):
            if json_result.get('permalink'):
                result['permalink'] = json_result['permalink']

            if json_result.get('positives'):
                result['positives'] = json_result['positives']
            else:
                result['positives'] = 0

            if json_result.get('total'):
                result['total'] = json_result['total']

        for context in observable.context:
            if context['source'] == 'virustotal_query':
                break
        else:
            result['source'] = 'virustotal_query'
            observable.add_context(result)
        return list(links)
