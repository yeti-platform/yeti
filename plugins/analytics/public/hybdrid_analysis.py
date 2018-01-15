import requests

from core import yeti_config
from core.observables import Hostname


class HybridAnalysisApi(object):
    """Base class for querying the Hybdrid Analysis API.
    limit rejection, as it could cause api key deactivation.
    """
    settings = {
        'hybdrid_analysis_api_key': {
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
        pass
