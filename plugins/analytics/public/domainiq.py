import json
import logging
import requests
from core.observables import Ip, Hostname, Email, Text
from core.analytics import OneShotAnalytics
from core.errors import GenericYetiError, ObservableValidationError

mapped_types = {
    "Ip": "ip_report",
    "Hostname": "domain_report",
    "Email": "email_report",
}


class DomainIQApi(object):
    """Base class for querying the DomainIQ API."""

    @staticmethod
    def fetch(observable, apikey):
        params = {
            "key": apikey,
            "output_mode": "json",
        }

        if isinstance(observable, Ip):
            params["service"] = "ip_report"
            params["ip"] = observable.value
        elif isinstance(observable, Hostname):
            params["service"] = "domain_report"
            params["domain"] = observable.value
        elif isinstance(observable, Email):
            params["service"] = "email_report"
            params["email"] = observable.value

        try:
            r = requests.get("https://www.domainiq.com/api", params=params)
            if r.ok:
                return r.json()
            else:
                raise GenericYetiError("{} - {}".format(r.status_code, r.content))
        except Exception as e:
            logging.erro(e)
            raise GenericYetiError("{} - {}".format(r.status_code, r.content))


class DomainIQ(DomainIQApi, OneShotAnalytics):
    default_values = {
        'name': 'DomainIQ',
        'description': 'Perform a DomainIQ query.',
    }

    settings = {
        "domainiq_apikey": {
            "name": "DomainIQ apikey",
            "description": "apikey for domainiq."
        }
    }

    ACTS_ON = ['Hostname', 'Ip', 'Email']

    @staticmethod
    def process_ip_response(observable, json_result):
        links = set()
        # pylint: disable=line-too-long
        resolve_host = json_result.get("data", {}).get(
            "ip_whois", {}).get("resolve_host")
        if resolve_host is not None:
                try:
                    node = Hostname.get_or_create(value=resolve_host)
                    links.update(
                        node.active_link_to(
                            observable, 'Hostname', 'DomainIQ')
                    )
                except ObservableValidationError as e:
                    logging.error((e, resolve_host))

        return links

    @staticmethod
    def process_hostname_response(observable, json_result):
        links = set()

        # pylint: disable=line-too-long
        for domain in json_result.get("data", {}).get("domains_on_ip", []):
            try:
                node = Hostname.get_or_create(value=domain)
                links.update(
                    node.active_link_to(observable, 'Hostname', 'DomainIQ')
                )
            except ObservableValidationError as e:
                logging.error((e, domain))
        for ip in json_result.get("data", {}).get("ips", []):
            try:
                node = Ip.get_or_create(value=ip)
                links.update(
                    node.active_link_to(observable, 'IP', 'DomainIQ'))
            except ObservableValidationError as e:
                logging.error((e, ip))
        if json_result.get("data", {}).get("registrar_normalized"):
            node = Text.get_or_create(
                value=json_result["data"]["registrar_normalized"]
            )
            links.update(
                node.active_link_to(observable, 'Registrant', 'DomainIQ'))

        return links

    @staticmethod
    def process_email_response(observable, json_result):
        links = set()

        # pylint: disable=line-too-long
        for domain_block in json_result.get("data", {}).get("related_domains", []):
            try:
                node = Hostname.get_or_create(value=domain_block["domain"])
                links.update(
                    node.active_link_to(
                        observable, 'Hostname', 'DomainIQ')
                )
            except ObservableValidationError as e:
                logging.error((e, domain_block["domain"]))
            try:
                node = Text.get_or_create(value=domain_block["registrant"])
                links.update(
                    node.active_link_to(
                        observable, 'Registrant', 'DomainIQ')
                )
            except ObservableValidationError as e:
                 logging.error((e, domain_block["registrant"]))

        return links

    @staticmethod
    def analyze(observable, results):
        json_result = DomainIQApi.fetch(
            observable, results.settings['domainiq_apikey']
        )

        if isinstance(observable, Ip):
            links = DomainIQ.process_ip_response(observable, json_result)
        elif isinstance(observable, Hostname):
            links = DomainIQ.process_hostname_response(observable, json_result)
        elif isinstance(observable, Email):
            links = DomainIQ.process_email_response(observable, json_result)

        result = {}

        json_string = json.dumps(
            json_result, sort_keys=True, indent=4, separators=(',', ': ')
        )
        result.update(raw=json_string)
        result['source'] = "DomainIQ"
        result['raw'] = json_string
        observable.add_context(result)

        return list(links)
