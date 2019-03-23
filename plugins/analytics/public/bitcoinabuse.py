import json
import logging

import datetime
import requests

from core.analytics import OneShotAnalytics
from core.observables import Bitcoin
from core.config.config import yeti_config

class BitCoinAbuseAPI(object):
    """Base class for querying the Bitcoinabuse.com API."""
    settings = {
        'bitcoinabuse_apikey': {
            'name': 'Bitcoinabuse.com API Key',
            'description': 'API Key for bitcoinabuse.com.'
        }
    }

    API = 'https://www.bitcoinabuse.com/api/'

    @staticmethod
    def get_abuse_type(abuse_type_id):
    # This is for future use once they update their api.
    # Currently they only return counts for reports.
    # If they start returning the abuse types we can get the mapping here.

        r = requests.get('{api_url}abuse-types'.format(api_url=BitCoinAbuseAPI.API) , proxies=yeti_config.proxy)
        if r.ok:
            abuse_types = r.json()
            for _type in abuse_types:
                if _type.get('id') == abuse_type_id:
                    return _type.get('label')

    @staticmethod
    def check(observable, api_key):
        if isinstance(observable, Bitcoin):
            url = '{api_url}reports/check?address={btc_address}&api_token={api_key}'.format(
                    api_url=BitCoinAbuseAPI.API,
                    btc_address=observable.value,
                    api_key=api_key
            )

            try:
                res = requests.get(url)
                if res.ok:
                    return res.json()
            except Exception as e:
                logging.error('Exception checking report {}'
                    .format(e.message))

class BitCoinAbuseQuery(BitCoinAbuseAPI, OneShotAnalytics):
    default_values = {
        'name': 'BitCoinAbuse',
        'group': 'BTC',
        'description': 'Looks up btc address for abuse reports.'
    }
    ACTS_ON = ['Bitcoin']

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = BitCoinAbuseAPI.check(
            observable,
            results.settings['bitcoinabuse_apikey']
        )

        if json_result:
            json_string = json.dumps(
                json_result,
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )

            results.update(raw=json_string)
            result = {}
            result['source'] = 'bitcoinabuse_query'
            result['raw'] = json_string

            if json_result.get('count', 0) > 0:
                observable.tag(['listed_for_abuse'])

            observable.add_context(result)
    return list(links)
