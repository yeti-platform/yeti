from pprint import pformat
from core.analytics import OneShotAnalytics
from core.observables import Hostname, Ip, Url
from core.entities import Company
import urllib
import json


BASE_IP_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
BASE_URL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
BASE_IP_PARAMS = {'ip': None, 'apikey': None}
BASE_URL_PARAMS = {'resource': None, 'apikey': None}
VT_QUERY = 'Virustotal Query'


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
        try:
            response = None
            if isinstance(observable, Hostname):
                params = BASE_URL_PARAMS
                params['resource'] = observable.value
                params['apikey'] = api_key
                response = urllib.urlopen('%s?%s' % (BASE_URL_URL, urllib.urlencode(params)))
            elif isinstance(observable, Ip):
                params = BASE_IP_PARAMS
                params['ip'] = observable.value
                response = urllib.urlopen('%s?%s' % (BASE_IP_URL, urllib.urlencode(params)))

            if response.code == 200:
                # self.last_query['time'] = datetime.now()
                # self.last_query['count'] += 1
                return response.read()
            else:
                return None
        except Exception as e:
            print 'Exception while getting ip report %s' % e.message
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
        response = VirustotalApi.fetch(observable, results.settings['virutotal_api_key'])
        results.update(raw=pformat(response))
        json_result = json.loads(response)
        result = {}

        if isinstance(observable, Ip):
            # Parse results for ip
            if json_result['as_owner'] and json_result['as_owner'] is not None:
                result['Owner'] = json_result['as_owner']
                o_isp = Company.get_or_create(name=json_result['as_owner'])
                links.update(observable.active_link_to(o_isp, 'hosting', VT_QUERY))

            if json_result['detected_urls'] and json_result['detected_urls'] is not None:
                result['detected_urls'] = json_result['detected_urls']
                for detected_url in json_result['detected_urls']:
                    o_url = Url.get_or_create(value=detected_url['url'])
                    links.update(o_url.active_link_to(o_url, 'hostname', VT_QUERY))

        elif isinstance(observable, Hostname):
            if json_result['permalink'] and json_result['permalink'] is not None:
                result['permalink'] = json_result['permalink']

            if json_result['positives'] and json_result['positives'] is not None:
                result['positives'] = json_result['positives']

            if json_result['total'] and json_result['total'] is not None:
                result['total'] = json_result['total']

        for context in observable.context:
            if context['source'] == 'virustotal_query':
                break
        else:
            result['source'] = 'virustotal_query'
            observable.add_context(result)
        return list(links)
