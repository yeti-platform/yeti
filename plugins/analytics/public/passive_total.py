import requests
from datetime import datetime

from core.helpers import get_value_at
from core.analytics import OneShotAnalytics
from core.observables import Observable, Hostname, Hash, Email


class PassiveTotalApi(object):
    settings = {
        "passivetotal_api_username": {
            "name": "PassiveTotal API Username",
            "description": "Username (email-address) used for PassiveTotal."
        },
        "passivetotal_api_key": {
            "name": "PassiveTotal API Key",
            "description": "API Key provided by PassiveTotal."
        }
    }

    API_URL = "https://api.passivetotal.org/v2"

    @staticmethod
    def get(uri, settings, params={}):
        url = PassiveTotalApi.API_URL + uri
        auth = (settings['passivetotal_api_username'], settings['passivetotal_api_key'])

        response = requests.get(url, auth=auth, params=params)
        response.raise_for_status()

        return response.json()


class PassiveTotalPassiveDNS(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "name": "PassiveTotal Passive DNS",
        "description": "Perform passive DNS (reverse) lookups on domain names or IP addresses."
    }

    ACTS_ON = ["Hostname", "Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        params = {
            'query': observable.value
        }

        data = PassiveTotalApi.get('/dns/passive', results.settings, params)

        for record in data['results']:
            first_seen = datetime.strptime(record['firstSeen'], "%Y-%m-%d %H:%M:%S")
            last_seen = datetime.strptime(record['lastSeen'], "%Y-%m-%d %H:%M:%S")

            new = Observable.add_text(record['resolve'])
            if isinstance(observable, Hostname):
                links.update(observable.link_to(new, "A record", 'PassiveTotal', first_seen, last_seen))
            else:
                links.update(new.link_to(observable, "A record", 'PassiveTotal', first_seen, last_seen))

        return list(links)


class PassiveTotalMalware(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "name": "PassiveTotal Get Malware",
        "description": "Find malware related to domain names or IP addresses."
    }

    ACTS_ON = ["Hostname", "Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        params = {
            'query': observable.value
        }

        data = PassiveTotalApi.get('/enrichment/malware', results.settings, params)

        for record in data['results']:
            collection_date = datetime.strptime(record['collectionDate'], "%Y-%m-%d %H:%M:%S")

            malware = Hash.get_or_create(value=record['sample'])
            links.update(malware.link_to(observable, "Contacted Host", record['source'], collection_date))

        return list(links)


class PassiveTotalSubdomains(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "name": "PassiveTotal Get Subdomains",
        "description": "Find all known subdomains."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        params = {
            'query': '*.{}'.format(observable.value)
        }

        data = PassiveTotalApi.get('/enrichment/subdomains', results.settings, params)

        for record in data['subdomains']:
            subdomain = Hostname.get_or_create(value='{}.{}'.format(record, observable.value))
            links.update(observable.active_link_to(subdomain, "Subdomain", 'PassiveTotal'))

        return list(links)


class PassiveTotalReverseWhois(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "name": "PassiveTotal Reverse Whois",
        "description": "Find all known domain names for a specific email address."
    }

    ACTS_ON = ["Email"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        params = {
            'query': observable.value,
            'field': 'email'
        }

        data = PassiveTotalApi.get('/whois/search', results.settings, params)

        for record in data['results']:
            print record
            domain = Hostname.get_or_create(value=record['domain'])
            links.update(domain.active_link_to(observable, "Registrant Email", 'PassiveTotal'))

            for ns in record['nameServers']:
                if ns != "No nameserver":
                    ns = Hostname.get_or_create(value=ns)
                    links.update(domain.active_link_to(ns, "NS record", 'PassiveTotal'))

        return list(links)


class PassiveTotalReverseNS(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "name": "PassiveTotal Reverse NS",
        "description": "Find all known domain names for a specific NS server."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        params = {
            'query': observable.value,
            'field': 'nameserver'
        }

        data = PassiveTotalApi.get('/whois/search', results.settings, params)

        for record in data['results']:
            domain = Hostname.get_or_create(value=record['domain'])
            links.update(domain.active_link_to(observable, "NS record", 'PassiveTotal'))

            registrant_email = get_value_at(record, 'registrant.email')
            if registrant_email:
                registrant = Email.get_or_create(value=registrant_email)
                links.update(domain.active_link_to(registrant, "Registrant Email", 'PassiveTotal'))

        return list(links)
