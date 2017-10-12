from pprint import pformat
import virustotal
from core.analytics import OneShotAnalytics


class VirustotalApi(object):
    settings = {
        "virutotal_api_key": {
            "name": "Virustotal API Key",
            "description": "API Key provided by virustotal.com."
        }
    }

    @staticmethod
    def fetch(observable, api_key):
        try:
            vt = virustotal.VirusTotal(api_key)
            r = vt.get(observable)
        except Exception:
            raise
        return r


class VirusTotalQuery(OneShotAnalytics, VirustotalApi):
    default_values = {
        "name": "Virustotal",
        "description": "Perform a Virustotal query."
    }

    ACTS_ON = ["Ip", "Hostname"]

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
