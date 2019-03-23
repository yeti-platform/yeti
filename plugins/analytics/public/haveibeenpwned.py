import json
import logging

import requests

from core.analytics import OneShotAnalytics
from core.observables import Email, Text


class HaveIBeenPwnedAPI(object):
    """Base class for querying the HaveIBeenPwned API."""

    API = 'https://haveibeenpwned.com/api/v2/'
    HEADERS = {
        'User-Agent': 'Yeti Analytics Worker'
    }

    @staticmethod
    def search_breaches(observable):
        if isinstance(observable, Email):
            url = '{api}breachedaccount/{account}'.format(
                api=HaveIBeenPwnedAPI.API, account=observable.value)
            
            try:
                res = requests.get(url, headers=HaveIBeenPwnedAPI.HEADERS)
                if res.ok:
                    return res.json()
            except Exception as e:
                logging.error('Exception while getting \
                    email report {}'.format(e.message))

    @staticmethod
    def search_pastes(observable):
        if isinstance(observable, Email):
            url = '{api}pasteaccount/{account}'.format(
                api=HaveIBeenPwnedAPI.API, account=observable.value)

            try:
                res = requests.get(url, headers=HaveIBeenPwnedAPI.HEADERS)
                if res.ok:
                    return res.json()
            except Exception as e:
                logging.error(
                    'Exception while getting \
                     email report {}'.format(e.message))


class HaveIBeenPwnedSearchBreaches(HaveIBeenPwnedAPI, OneShotAnalytics):
    default_values = {
        'name': 'HaveIBeenPwned-Breaches',
        'group': 'Search Leaks',
        'description': 'Perform a HaveIBeenPwnedAPI query.',
    }

    ACTS_ON = ['Email']

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = HaveIBeenPwnedAPI.search_breaches(observable)
        json_string = json.dumps(
            json_result, sort_keys=True, indent=4, separators=(',', ': '))
        results.update(raw=json_string)
        result = {}
        result['source'] = 'HaveIBeenPwned_query'
        result['raw'] = json_string

        for hit in json_result:
            if hit.get('Name'):
                tags = ['comprimised', hit.get('Name', '').lower() + '_breach']
                observable.tag(tags)
                o_breach = Text.get_or_create(
                    value='Account compromised in {} breach on or around {}'
                    .format(
                        hit.get('Name', ''),
                        hit.get('AddedDate', '')))

                links.update(
                    observable.active_link_to(
                        o_breach, 'found in breach', 'haveibeenpwned_hit')
                )

        observable.add_context(result)
        return list(links)


class HaveIBeenPwnedSearchPastes(HaveIBeenPwnedAPI, OneShotAnalytics):
    default_values = {
        'name': 'HaveIBeenPwned-Pastes',
        'group': 'Search Leaks',
        'description': 'Perform a HaveIBeenPwnedAPI query.',
    }

    ACTS_ON = ['Email']

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = HaveIBeenPwnedAPI.search_pastes(observable)
        json_string = json.dumps(
            json_result, sort_keys=True, indent=4, separators=(',', ': '))
        
        results.update(raw=json_string)
        result = {}
        result['source'] = 'HaveIBeenPwned_query'
        result['raw'] = json_string

        for hit in json_result:
            if hit.get('Source'):
                tags = ['comprimised', 'found_on_pastebin']
                observable.tag(tags)
                o_breach = Text.get_or_create(
                    value='Account compromised found \
                    on pastebin on or around {} paste id {} , paste title {}'
                    .format(
                        hit.get('Date', ''),
                        hit.get('Id', ''), hit.get('Title', '')))
                links.update(
                    observable.active_link_to(
                        o_breach, 'found on pastebin', 'haveibeenpwned_hit')
                )

        observable.add_context(result)
        return list(links)
