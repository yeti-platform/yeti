import json

import requests
import logging

from core.analytics import OneShotAnalytics
from core.errors import ObservableValidationError
from core.observables import Url, Hash


class MalshareAPI(object):
    """Base class for querying the Malshare API.
    This is the public API, 1000 samples per day.

    Limit rejection, as it could cause api key deactivation.
    """
    settings = {
        'malshare_api_key': {
            'name': 'Malshare API Key',
            'description': 'API Key provided by malshare.com'
        }
    }

    @staticmethod
    def fetch(observable, api_key):
        """
        :param observable: The extended observable klass
        :param api_key: The api key obtained from Malshare
        :return:  malshare json response or None if error
        """

        try:
            params = {
                'hash': observable.value,
                'api_key': api_key,
                'action': 'details'
            }
            response = requests.get('https://malshare.com/api.php', params=params)
            if response.ok:
                return response.json()
            else:
                return None
        except Exception as e:
            # TODO(sebdraven): Catch a better exception
            print 'Exception while getting ip report {}'.format(e.message)
        return None


class MalshareQuery(OneShotAnalytics, MalshareAPI):
    default_values = {
        'name': 'MalShare',
        'description': 'Perform a MalShare query.',
    }

    ACTS_ON = ['Hash']

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = MalshareAPI.fetch(
            observable, results.settings['malshare_api_key'])

        if json_result is None:
            return list(links)

        json_string = json.dumps(
            json_result, sort_keys=True, indent=4, separators=(',', ': '))
        results.update(raw=json_string)
        result = {'raw': json_string}

        if 'SOURCES' in json_result:
            for source in json_result['SOURCES']:
                new_url = None
                try:
                    new_url = Url.get_or_create(value=source.strip())
                    links.update(
                        observable.active_link_to(
                            new_url, 'c2', 'malshare_query'))
                except ObservableValidationError:
                    logging.error(
                        "An error occurred when trying to add {} to the database".
                        format(source.strip()))
            result['nb C2'] = len(json_result['SOURCES'])
        try:
            new_hash = Hash.get_or_create(value=json_result['MD5'])
            links.update(
                new_hash.active_link_to(observable, 'md5', 'malshare_query'))
            new_hash = Hash.get_or_create(value=json_result['SHA1'])
            links.update(
                new_hash.active_link_to(observable, 'sha1', 'malshare_query'))
            new_hash = Hash.get_or_create(value=json_result['SHA256'])
            links.update(
                new_hash.active_link_to(observable, 'sha256', 'malshare_query'))
        except ObservableValidationError:
            logging.error(
                "An error occurred when trying to add hashes {} to the database".
                format(json_string))

        return list(links)
