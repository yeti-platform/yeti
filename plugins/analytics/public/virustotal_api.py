from pprint import pformat
from core.analytics import OneShotAnalytics
from core.observables import Hostname, Ip
import urllib


BASE_IP_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
BASE_URL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
BASE_IP_PARAMS = {'ip': None, 'apikey': None}
BASE_URL_PARAMS = {'resource': None, 'apikey': None}


class VirustotalApi(object):
    """
    Base class for querying the VirusTotal API.
    This is the public API, so there is a limit for up to 3
    requests per minute.

    TODO: Register a redis key with the last query time and prevent
    limit rejection, as it could cause api key deactivation.
    """
    settings = {
        "virutotal_api_key": {
            "name": "Virustotal API Key",
            "description": "API Key provided by virustotal.com."
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
        "name": "Virustotal",
        "description": "Perform a Virustotal query."
    }

    ACTS_ON = "Ip"

    @staticmethod
    def analyze(observable, results):
        links = set()
        result = VirustotalApi.fetch(observable, results.settings['virutotal_api_key'])
        results.update(raw=pformat(result))

        if 'tags' in result and result['tags'] is not None:
            observable.tag(result['tags'])

        for context in observable.context:
            if context['source'] == 'virustotal_query':
                break
        else:
            result['source'] = 'virustotal_query'
            observable.add_context(result)
        return list(links)
