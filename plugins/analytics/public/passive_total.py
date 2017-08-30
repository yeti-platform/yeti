import requests
from datetime import datetime

from core.analytics import OneShotAnalytics
from core.observables import Observable, Hostname, Hash, Email, Text


def whois_links(observable, whois):
    links = set()

    to_extract = [
        {
            "field": "organization",
            "type": Text,
            "label": "Registrant Organization",
        },
        {
            "field": "registrar",
            "type": Text,
            "label": "Registrar",
        },
        {
            "field": "contactEmail",
            "type": Email,
            "label": "Registrant Email",
        },
        {
            "field": "name",
            "type": Text,
            "label": "Registrant Name",
        },
        {
            "field": "telephone",
            "type": Text,
            "label": "Registrant Phone",
            "record_type": "phone"
        }
    ]

    for field in to_extract:
        if field['field'] in whois and whois[field['field']] != 'N/A':
            node = field['type'].get_or_create(value=whois[field['field']])
            if field['type'] == Text:
                if "record_type" in field:
                    node.update(record_type=field['record_type'])
                else:
                    node.update(record_type=field['field'])

            links.update(observable.active_link_to(node, field['label'], 'PassiveTotal'))

    if 'nameServers' in whois:
        nameservers = []
        for ns in whois['nameServers']:
            if ns not in ["No nameserver", "not.defined"]:
                try:
                    nameservers.append(Hostname.get_or_create(value=ns))
                except Exception, e:
                    print e

        if nameservers:
            links.update(observable.active_link_to(nameservers, "NS record", 'PassiveTotal'))

    return list(links)


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
        "group": "PassiveTotal",
        "name": "Passive DNS",
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
                links.update(observable.link_to(new, "{} record".format(record['recordType']), 'PassiveTotal', first_seen, last_seen))
            else:
                links.update(new.link_to(observable, "{} record".format(record['recordType']), 'PassiveTotal', first_seen, last_seen))

        return list(links)


class PassiveTotalMalware(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "group": "PassiveTotal",
        "name": "Get Malware",
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
        "group": "PassiveTotal",
        "name": "Get Subdomains",
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


class PassiveTotalWhois(OneShotAnalytics, PassiveTotalApi):
    default_values = {
        "group": "PassiveTotal",
        "name": "Whois",
        "description": "Get Whois information for a specific domain name."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        params = {
            'query': observable.value,
        }

        data = PassiveTotalApi.get('/whois', results.settings, params)

        context = {
            'source': 'PassiveTotal Whois',
            'raw': data
        }
        observable.add_context(context)

        return whois_links(observable, data)


class PassiveTotalReverseWhois(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "group": "PassiveTotal",
        "name": "Reverse Whois",
        "description": "Find all known domain names for a specific whois field."
    }

    ACTS_ON = ["Email", "Text"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        if isinstance(observable, Email):
            field = 'email'
        elif observable.record_type:
            field = observable.record_type
        else:
            raise ValueError("Could not determine field for this observable")

        params = {
            'query': observable.value,
            'field': field
        }

        data = PassiveTotalApi.get('/whois/search', results.settings, params)

        for record in data['results']:
            domain = Hostname.get_or_create(value=record['domain'])
            links.update(whois_links(domain, record))

        return list(links)


class PassiveTotalReverseNS(OneShotAnalytics, PassiveTotalApi):

    default_values = {
        "group": "PassiveTotal",
        "name": "Reverse NS",
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
            links.update(whois_links(domain, record))

        return list(links)
