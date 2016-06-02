import ssl
import hmac
import json
import hashlib
import requests
from pythonwhois.parse import parse_raw_whois
from mongoengine import FieldDoesNotExist
from datetime import datetime
from tldextract import extract

from core.helpers import iterify, get_value_at
from core.analytics import OneShotAnalytics
from core.entities import Company
from core.observables import Hostname, Email, Text

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


def link_from_data(observable, data, path, klass, description):
    data = get_value_at(data, path)

    if data is None:
        return []

    links = set()

    for value in iterify(data):
        try:
            node = klass.get_or_create(value=value)
        except FieldDoesNotExist:
            node = klass.get_or_create(name=value)

        links.update(observable.active_link_to(node, description, 'DomainTools'))

    return list(links)


class TlsAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2)


class DomainToolsApi(object):
    settings = {
        "domaintools_api_username": {
            "name": "DomainTools API Username",
            "description": "Username provided for API by DomainTools."
        },
        "domaintools_api_key": {
            "name": "DomainTools API Key",
            "description": "API Key provided by DomainTools."
        }
    }

    API_URL = "https://api.domaintools.com/v1"

    @staticmethod
    def get(uri, settings, params={}):
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        _params = "{}{}/v1{}".format(settings['domaintools_api_username'].encode('ascii'), timestamp, uri)
        signature = hmac.new(settings['domaintools_api_key'].encode('ascii'), _params, digestmod=hashlib.sha1).hexdigest()
        _params = {
            'api_username': settings['domaintools_api_username'],
            'signature': signature,
            'timestamp': timestamp
        }
        params.update(_params)

        s = requests.Session()
        s.mount('https://', TlsAdapter())
        r = s.get(DomainToolsApi.API_URL + uri, params=params)
        r = r.json()

        if 'error' in r:
            raise LookupError(r['error']['message'])

        return r


class DTReverseIP(OneShotAnalytics, DomainToolsApi):

    default_values = {
        "name": "DomainTools Reverse IP",
        "description": "Reverse IP lookup."
    }

    ACTS_ON = ["Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        data = DomainToolsApi.get("/{}/host-domains/".format(observable.value), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        for record in data['response']['ip_addresses']['domain_names']:
            node = Hostname.get_or_create(value=record)
            links.update(node.active_link_to(observable, 'A record', 'DomainTools'))

        return list(links)


class DTReverseNS(OneShotAnalytics, DomainToolsApi):

    default_values = {
        "name": "DomainTools Reverse NS",
        "description": "Reverse Name Server lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        data = DomainToolsApi.get("/{}/name-server-domains".format(observable.value), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        for record in data['response']['primary_domains'] + data['response']['secondary_domains']:
            node = Hostname.get_or_create(value=record)
            links.update(node.active_link_to(observable, 'NS record', 'DomainTools'))

        return list(links)


class DTWhoisHistory(OneShotAnalytics, DomainToolsApi):

    default_values = {
        "name": "DomainTools Whois History",
        "description": "Whois History lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        parts = extract(observable.value)

        if parts.subdomain == '':
            data = DomainToolsApi.get("/{}/whois/history".format(observable.value), results.settings)
            results.update(raw=json.dumps(data, indent=2))

            for record in data['response']['history']:
                created = datetime.strptime(record['whois']['registration']['created'], "%Y-%m-%d")
                expires = datetime.strptime(record['whois']['registration']['expires'], "%Y-%m-%d")

                registrar = Company.get_or_create(name=record['whois']['registration']['registrar'])
                registrant = Text.get_or_create(value=record['whois']['registrant'])

                links.update(observable.link_to(registrar, 'Registrar', 'DomainTools', created, expires))
                links.update(observable.link_to(registrant, 'Registrant', 'DomainTools', created, expires))

                parsed = parse_raw_whois([record['whois']['record']], normalized=True)
                email = get_value_at(parsed, 'contacts.registrant.email')
                if email:
                    email = Email.get_or_create(value=email)
                    links.update(observable.link_to(email, 'Registrant Email', 'DomainTools', created, expires))

        return list(links)


class DTReverseWhois(OneShotAnalytics, DomainToolsApi):

    default_values = {
        "name": "DomainTools ReverseWhois",
        "description": "Reverse Whois lookup."
    }

    ACTS_ON = ["Text", "Email"]

    @staticmethod
    def analyze(observable, results):
        links = []

        params = {
            'terms': observable.value,
            'mode': 'purchase'
        }
        data = DomainToolsApi.get("/reverse-whois/", results.settings, params)

        for domain in data['response']['domains']:
            node = Hostname.get_or_create(value=domain)
            links += node.active_link_to(observable, 'Registrant Information', 'DomainTools')

        return links


class DTWhois(OneShotAnalytics, DomainToolsApi):

    default_values = {
        "name": "DomainTools Whois",
        "description": "Whois lookup with parsed results."
    }

    ACTS_ON = ["Hostname", "Ip"]

    @staticmethod
    def analyze_domain(observable, data):
        fields = [
            ('response.parsed_whois.contacts.registrant.email', Email, 'Registrant Email'),
            ('response.parsed_whois.contacts.registrant.name', Text, 'Registrant Name'),
            ('response.parsed_whois.contacts.registrant.org', Text, 'Registrant Organization'),
            ('response.parsed_whois.contacts.registrant.phone', Text, 'Registrant Phone Number'),
            ('response.parsed_whois.name_servers', Hostname, 'NS record')
        ]

        links = []

        for field in fields:
            links += link_from_data(observable, data, *field)

        return links

    @staticmethod
    def analyze_ip(observable, data):
        return link_from_data(observable, data, 'response.registrant', Company, 'Hosting')

    @staticmethod
    def analyze(observable, results):
        links = []
        parts = extract(observable.value)

        if parts.subdomain == '':
            should_add_context = False
            for context in observable.context:
                if context['source'] == 'whois':
                    break
            else:
                should_add_context = True
                context = {'source': 'whois'}

            data = DomainToolsApi.get("/{}/whois/parsed".format(observable.value), results.settings)
            results.update(raw=json.dumps(data, indent=2))
            context['raw'] = data['response']['whois']

            if isinstance(observable, Hostname):
                links = DTWhois.analyze_domain(observable, data)
            else:
                links = DTWhois.analyze_ip(observable, data)

            if should_add_context:
                observable.add_context(context)
            else:
                observable.save()

            print links

        return links
