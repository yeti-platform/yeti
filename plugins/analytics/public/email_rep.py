import json
import logging
import requests

from core.analytics import OneShotAnalytics
from core.errors import GenericYetiError


class EmailRepAPI(object):
    """Base class for querying the EmailRep API."""

    @staticmethod
    def fetch(observable):

        try:
            r = requests.get("https://emailrep.io/{}".format(observable.value))
            if r.ok:
                return r.json()
            else:
                raise GenericYetiError("{} - {}".format(r.status_code, r.content))
        except requests.exceptions.RequestException as e:
            logging.error(e)
            raise GenericYetiError("{} - {}".format(r.status_code, r.content))


class EmailRep(EmailRepAPI, OneShotAnalytics):
    default_values = {
        'name': 'EmailRep',
        'description': 'Perform a EmailRep query.',
    }

    ACTS_ON = ['Email']

    @staticmethod
    def analyze(observable, results):
        json_result = EmailRepAPI.fetch(observable)
        result = {}

        json_string = json.dumps(json_result, sort_keys=True, indent=4, separators=(',', ': '))
        result.update(raw=json_string)
        result['source'] = "EmailRep"
        result['raw'] = json_string
        observable.add_context(result)

        return list()
