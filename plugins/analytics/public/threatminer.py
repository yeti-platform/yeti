import json
import logging
from hashlib import sha1

import requests
from dateutil import parser

from core.analytics import OneShotAnalytics
from core.config.config import yeti_config
from core.errors import GenericYetiError
from core.errors import ObservableValidationError
from core.observables import Hash, Ip, Hostname, Url


def aux_checker(json_result):
    if not json_result or not json_result.get("results"):
        raise GenericYetiError("Results missed")

    json_string = json.dumps(
        json_result, sort_keys=True, indent=4, separators=(",", ": ")
    )

    result = {
        "raw": json_string,
        "source": "threatminer_query",
    }

    _results = json_result.get("results")

    return _results, result


class ThreatMinerApi(object):
    API_URL = "https://api.threatminer.org/v2/"

    @staticmethod
    def fetch(observable, params, uri):
        try:
            url = ThreatMinerApi.API_URL + uri
            response = requests.get(url, params=params, proxies=yeti_config.get('proxy'))
            if not response.ok:
                raise GenericYetiError("Status code: ".format(response.status_code))
            return response.json()
        except Exception as e:
            raise GenericYetiError(
                "Hit an error checking {},{}".format(observable.value, e)
            )


"""
    Pulls metadata related to a file hash.
    This consists of various hash types and file properties including filename.
    However it looks like file name is sometimes a url.
"""


class MetaData(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "Retrieve metadata.",
        "description": "Checks for any meta data stored in ThreatMiner.",
    }

    ACTS_ON = ["Hash"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        params = {"q": observable.value, "rt": 1}
        json_result = ThreatMinerApi.fetch(observable, params, "sample.php")
        try:
            _results, result = aux_checker(json_result)
        except GenericYetiError as e:
            logging.error(e.value)
            return links

        for r in _results:
            hashes = {"md5": r["md5"], "sha1": r["sha1"], "sha256": r["sha256"]}

            for family, _hash in hashes.items():
                if _hash == observable.value:
                    continue
                try:
                    new_hash = Hash.get_or_create(value=_hash)
                    new_hash.tag(observable.get_tags())
                    links.update(
                        new_hash.active_link_to(observable, family, "threatminer_query")
                    )
                except ObservableValidationError as e:
                    logging.error("Caught an exception: {}".format(e))

            observable.add_context(result)
        return list(links)


"""
    Searches for related http requests sourced from a particular sample.
"""


class HttpTraffic(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "Observed Http Traffic",
        "description": "Looks up any http traffic related to a sample.",
    }

    ACTS_ON = ["Hash"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        params = {"q": observable.value, "rt": 2}
        json_result = ThreatMinerApi.fetch(observable, params, "sample.php")

        _results, result = aux_checker(json_result)

        for r in _results:
            _http_requests = r.get("http_traffic")
            if not _http_requests:
                continue

            for http_request in _http_requests:
                if http_request.get("domain"):
                    try:
                        o_host = Hostname.get_or_create(
                            value=http_request.get("domain")
                        )
                        o_host.tag(observable.get_tags())
                        links.update(
                            o_host.active_link_to(
                                observable, "seen connecting to", "threatminer_query"
                            )
                        )
                    except ObservableValidationError as e:
                        logging.error("Caught an exception: {}".format(e))

                if http_request.get("ip"):
                    try:
                        o_ip = Ip.get_or_create(value=http_request.get("ip"))
                        o_ip.tag(observable.get_tags())
                        links.update(
                            o_ip.active_link_to(
                                observable, "seen connecting to", "threatminer_query"
                            )
                        )
                    except ObservableValidationError as e:
                        logging.error("Caught an exception: {}".format(e))

        observable.add_context(result)
        return list(links)


"""
    Search for domains and ip related to a hash.
"""


class RelatedHosts(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "Related Hosts",
        "description": "Lookup related domains.",
    }

    ACTS_ON = ["Hash"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        params = {"q": observable.value, "rt": 3}
        json_result = ThreatMinerApi.fetch(observable, params, "sample.php")
        _results, result = aux_checker(json_result)

        for r in _results:
            for ip in r.get("hosts"):
                try:
                    o_ip = Ip.get_or_create(value=ip)
                    o_ip.tag(observable.get_tags())
                    links.update(
                        o_ip.active_link_to(
                            observable, "seen connecting to", "ThreatMiner"
                        )
                    )
                except ObservableValidationError as e:
                    logging.error("Caught an exception: {}".format(e))

            for domain in r.get("domains"):
                try:
                    if domain.get("domain"):
                        o_host = Hostname.get_or_create(value=domain.get("domain"))
                        o_host.tag(observable.get_tags())
                        links.update(
                            o_host.active_link_to(
                                observable, "seen connecting to", "ThreatMiner"
                            )
                        )
                    if domain.get("ip"):
                        o_ip = Ip.get_or_create(value=domain.get("ip"))
                        o_ip.tag(o_host.get_tags())
                        links.update(
                            o_host.active_link_to(o_ip, "resolved to", "ThreatMiner")
                        )
                except ObservableValidationError as e:
                    logging.error("Caught an exception: {}".format(e))

        observable.add_context(result)
        return list(links)


"""
    Search for subdomains related to a domain.
"""


class LookupSubdomains(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "Lookup Subdomains",
        "description": "Lookup known subdomains.",
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        params = {"q": observable.value, "rt": 5}
        json_result = ThreatMinerApi.fetch(observable, params, "domain.php")

        _results, result = aux_checker(json_result)

        for r in _results:
            try:
                o_hostname = Hostname.get_or_create(value=r)
                links.update(
                    observable.link_to(
                        o_hostname,
                        description="related subdomain",
                        source="ThreatMiner",
                    )
                )

            except ObservableValidationError as e:
                logging.error("Caught an exception: {}".format(e))

        observable.add_context(result)
        return list(links)


"""
    Performs a PDNS lookup on a domain or ip.
"""


class ThreatMinerPDNS(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "ThreatMiner PDNS",
        "description": "Perform a PDNS lookup.",
    }

    ACTS_ON = ["Hostname", "Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        if isinstance(observable, Ip):
            params = {"q": observable.value, "rt": 2}
            json_result = ThreatMinerApi.fetch(observable, params, "host.php")
            _results, result = aux_checker(json_result)

            for r in _results:
                try:
                    o_hostname = Hostname.get_or_create(value=r.get("domain"))
                    links.update(
                        observable.link_to(
                            o_hostname,
                            description="a record",
                            source="ThreatMiner",
                            first_seen=parser.parse(r["first_seen"]),
                            last_seen=parser.parse(r["last_seen"]),
                        )
                    )
                except ObservableValidationError as e:
                    logging.error("Caught an exception: {}".format(e))

            observable.add_context(result)

        elif isinstance(observable, Hostname):
            params = {"q": observable.value, "rt": 2}
            json_result = ThreatMinerApi.fetch(observable, params, "domain.php")

            _results, result = aux_checker(json_result)

            for r in _results:
                try:
                    o_ip = Ip.get_or_create(value=r.get("ip"))
                    links.update(
                        observable.link_to(
                            o_ip,
                            description="a record",
                            source="ThreatMiner",
                            first_seen=r["first_seen"],
                            last_seen=r["last_seen"],
                        )
                    )
                except ObservableValidationError as e:
                    logging.error("Caught an exception: {}".format(e))

            observable.add_context(result)
        return list(links)


"""
    Search for related urls to a domain or ip.
"""


class SearchUri(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "ThreatMiner Uri",
        "description": "Perform lookup for urls.",
    }

    ACTS_ON = ["Hostname", "Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        if isinstance(observable, Hostname):
            params = {"q": observable.value, "rt": 3}
            json_result = ThreatMinerApi.fetch(observable, params, "domain.php")

            _results, result = aux_checker(json_result)

            for r in _results:
                try:
                    o_url = Url.get_or_create(value=r.get("uri"))
                    o_url.tag(observable.get_tags())
                    links.update(
                        observable.link_to(
                            o_url,
                            description="related url",
                            source="ThreatMiner",
                            last_seen=r["last_seen"],
                        )
                    )
                except ObservableValidationError as e:
                    logging.error("Caught an exception: {}".format(e))

            observable.add_context(result)

        elif isinstance(observable, Ip):
            params = {"q": observable.value, "rt": 3}
            json_result = ThreatMinerApi.fetch(observable, params, "host.php")

            _results, result = aux_checker(json_result)

            for r in _results:
                try:
                    o_url = Url.get_or_create(value=r.get("uri"))
                    o_url.tag(observable.get_tags())
                    links.update(
                        observable.link_to(
                            o_url,
                            description="related url",
                            source="ThreatMiner",
                            last_seen=r["last_seen"],
                        )
                    )
                except ObservableValidationError as e:
                    logging.error("Caught an exception: {}".format(e))

            observable.add_context(result)
        return list(links)


"""
    Search for samples related to a domain or ip.
"""


class RelatedSamples(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "Related Samples",
        "description": "Lookup samples related to a domain or ip.",
    }

    ACTS_ON = ["Hostname", "Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        if isinstance(observable, Hostname):
            params = {"q": observable.value, "rt": 4}
            json_result = ThreatMinerApi.fetch(observable, params, "domain.php")

            _results, result = aux_checker(json_result)

            for r in _results:
                hashes = {"sha256": r}

                for family, _hash in hashes.items():
                    if _hash == observable.value:
                        continue
                    try:
                        new_hash = Hash.get_or_create(value=_hash)
                        new_hash.tag(observable.get_tags())
                        links.update(
                            new_hash.active_link_to(
                                observable, family, "threatminer_query"
                            )
                        )
                    except ObservableValidationError as e:
                        logging.error("Caught an exception: {}".format(e))

            observable.add_context(result)

        elif isinstance(observable, Ip):
            params = {"q": observable.value, "rt": 4}
            json_result = ThreatMinerApi.fetch(observable, params, "host.php")
            _results, result = aux_checker(json_result)

            for r in _results:
                hashes = {"sha256": r}

                for family, _hash in hashes.items():
                    if _hash == observable.value:
                        continue
                    try:
                        new_hash = Hash.get_or_create(value=_hash)
                        new_hash.tag(observable.get_tags())
                        links.update(
                            new_hash.active_link_to(
                                observable, family, "threatminer_query"
                            )
                        )
                    except ObservableValidationError as e:
                        logging.error("Caught an exception: {}".format(e))

            observable.add_context(result)

        return list(links)


"""
    Performs a reverse whois search on an email address.
    Do to GDPR limitations we are forced to search on a sha1 hash of the email.
"""


class ThreatMinerReverseWHOIS(OneShotAnalytics, ThreatMinerApi):
    default_values = {
        "group": "ThreatMiner",
        "name": "ThreatMiner Email Reverse WHOIS",
        "description": "Perform reverse whois lookups on email.",
    }

    ACTS_ON = ["Email"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        params = {"q": sha1(observable.value).hexdigest()}
        json_result = ThreatMinerApi.fetch(observable, params, "email.php")

        _results, result = aux_checker(json_result)

        for r in _results:
            try:
                o_hostname = Hostname.get_or_create(value=r)
                links.update(
                    observable.link_to(
                        o_hostname,
                        description="collected via reverse whois.",
                        source="ThreatMiner",
                    )
                )
            except ObservableValidationError as e:
                logging.error("Caught an exception: {}".format(e))

        observable.add_context(result)
        return list(links)
