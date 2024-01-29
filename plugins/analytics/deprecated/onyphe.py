"""
onyphe.client
~~~~~~~~~~~~~

This module implements the Onyphe API.

:copyright: (c) 2017- by Sebastien Larinier
"""

import json
import logging
import requests
from requests.utils import quote
from six.moves.urllib.parse import urljoin

from core.analytics import OneShotAnalytics
from core.observables import Hostname, Ip

default_types = {
    "Hostname": Hostname,
    "Ip": Ip,
}


class APIError(Exception):
    """This exception gets raised whenever a non-200 status code was returned by the Onyphe API."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class Onyphe:
    """Wrapper around the Onyphe REST API.
    The Onyphe API key that can be obtained from your account page (https://www.onyphe.io)
    :param key: str
    :type key: str
    """

    def __init__(self, api_key, version="v2"):
        self.api_key = api_key
        self.base_url = "https://www.onyphe.io/api/"
        self.version = version
        self._session = requests.Session()

        self.methods = {
            "get": self._session.get,
            "post": self._session.post,
        }

    def _choose_url(self, uri):
        self.url = urljoin(self.base_url, uri)

    def _request(self, method, payload, headers={}):
        data = None

        try:
            response = self.methods[method](self.url, params=payload, headers=headers)
        except Exception:
            raise APIError("Unable to connect to Onyphe")

        if response.status_code == requests.codes.NOT_FOUND:
            raise APIError("Page Not found %s" % self.url)
        elif response.status_code == requests.codes.FORBIDDEN:
            raise APIError("Access Forbidden")
        elif response.status_code == requests.codes.too_many_requests:
            raise APIError("Too Many Requests")
        elif response.status_code != requests.codes.OK:
            try:
                error = response.json()["message"]
            except Exception:
                error = "Invalid API key"

            raise APIError(error)
        try:
            data = response.json()

        except Exception:
            raise APIError("Unable to parse JSON")

        return data

    def _prepare_request(self, uri, **kwargs):
        headers = {"Authorization": f"apikey {self.api_key}"}
        payload = {}

        if "page" in kwargs:
            payload["page"] = kwargs["page"]

        self._choose_url(uri)

        data = self._request("get", payload, headers=headers)
        if data:
            return data

    def _search(self, query, **kwargs):
        return self._prepare_request(
            quote("/".join([self.version, "search", query])), **kwargs
        )

    def synscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/synscan/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of the search about synscans.
        """
        return self._prepare_request("/".join([self.version, "simple", "synscan", ip]))

    def pastries(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/pastries/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of the search in pasties recorded by the service.
        """
        return self._prepare_request("/".join([self.version, "simple", "pastries", ip]))

    def user(self):
        """Call API Onyphe https://www.onyphe.io/api/v2/user

        :returns: dict -- a dictionary containing the results of user
        """
        return self._prepare_request("/".join([self.version, "user"]))

    def geoloc(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/geoloc/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of geolocation of IP
        """
        return self._prepare_request("/".join([self.version, "simple", "geoloc", ip]))

    def inetnum(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/inetnum/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of inetnum of IP
        """
        return self._prepare_request("/".join([self.version, "simple", "inetnum", ip]))

    def threatlist(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/threatlist/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of the IP in threatlists
        """
        return self._prepare_request(
            "/".join([self.version, "simple", "threatlist", ip])
        )

    def forward(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/resolver/forward/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the results of forward of IP
        """
        return self._prepare_request(
            "/".join([self.version, "simple", "resolver", "forward", ip])
        )

    def reverse(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/resolver/reverse/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing the domains of reverse DNS of IP
        """
        return self._prepare_request(
            "/".join([self.version, "simple", "resolver", "reverse", ip])
        )

    def ip(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/summary/ip/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing all informations of IP
        """
        return self._prepare_request("/".join([self.version, "summary", "ip", ip]))

    def datascan(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/datascan/{IP,STRING}

        :param data: IPv4/IPv6 address
        :type data: str
        :returns: dict -- a dictionary containing Information scan on IP or string
        """
        return self._prepare_request(
            "/".join([self.version, "simple", "datascan", data])
        )

    def onionscan(self, onion):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/onionscan/{DOMAIN,HOSTNAME}

        :param onion: onion address
        :type onion: str
        :returns: dict -- a dictionary containing all information of onion site
        """
        return self._prepare_request(
            "/".join([self.version, "simple", "onionscan", onion])
        )

    def ctl(self, domain):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/ctl/{DOMAIN,HOSTNAME}

        :param domain: domain name
        :type domain: str
        :returns: dict -- a dictionary containing all informations of domain name certificates
        """
        return self._prepare_request("/".join([self.version, "simple", "ctl", domain]))

    def sniffer(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/sniffer/{IP}

        :param ip: str IPv4 or IPv6 address
        :type ip: str
        :returns: dict -- a dictionary containing all informations of IP
        """
        return self._prepare_request("/".join([self.version, "simple", "sniffer", ip]))

    def md5(self, md5):
        """Call API Onyphe https://www.onyphe.io/api/v2/simple/datascan/datamd5/{MD5}

        :param md5: md5 hash
        :type md5: str
        :returns: dict -- a dictionary containing all informations of md5 hash
        """
        return self._prepare_request(
            "/".join([self.version, "simple", "datascan", "datamd5", "md5", md5])
        )

    def search_datascan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/datascan/<query>
        :param query: example product:Apache port:443 os:Windows.
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:datascan {query}"
        return self._search(query, **kwargs)

    def search_synscan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/syscan/<query>
        :param query: example ip:46.105.48.0/21 os:Linux port:23.
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:synscan {query}"
        return self._search(query, **kwargs)

    def search_inetnum(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/inetnum/<query>
        :param query: example organization:"OVH SAS"
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:inetnum {query}"
        return self._search(query, **kwargs)

    def search_threatlist(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search/<query>
        :param query: example: country:RU or ip:94.253.102.185
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:threatlist {query}"
        return self._search(query, **kwargs)

    def search_pastries(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search/<query>
        :param query: example: domain:amazonaws.com or ip:94.253.102.185
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:pastries {query}"
        return self._search(query, **kwargs)

    def search_resolver(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search/<query>
        :param query: example: domain:amazonaws.com
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:resolver {query}"
        return self._search(query, **kwargs)

    def search_sniffer(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search/<query>
        :param query: example: ip:14.164.0.0/14
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:sniffer {query}"
        return self._search(query, **kwargs)

    def search_ctl(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search/<query>
        :param query: example: host:vpn
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:ctl {query}"
        return self._search(query, **kwargs)

    def search_onionscan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v2/search//<query>
        :param query: example: data:market
        :type: str
        :return: dict -- a dictionary with result
        """
        query = f"category:onionscan {query}"
        return self._search(query, **kwargs)


class OnypheAPI(object):
    """Base class for querying the Onyphe API."""

    settings = {
        "onyphe_api_key": {
            "name": "Onyphe API Key",
            "description": "API Key provided by onyphe.io",
        }
    }

    @staticmethod
    def fetch(on_client, observable):
        result = None
        if isinstance(observable, Ip):
            result = on_client.ip(observable.value)

        elif isinstance(observable, Hostname):
            result = on_client.ctl(observable.value)

        if result:
            if result["error"] != 0:
                logging.error(result["message"])
                return None

        return result["results"]


class OnypheQuery(OnypheAPI, OneShotAnalytics):
    default_values = {
        "name": "Onyphe",
        "description": "Perform a Onyphe query.",
    }

    ACTS_ON = ["Ip", "Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        on_client = Onyphe(results.settings["onyphe_api_key"])
        json_result = OnypheAPI.fetch(on_client, observable)

        if json_result:
            result = {}
            json_string = json.dumps(
                json_result, sort_keys=True, indent=4, separators=(",", ": ")
            )
            results.update(raw=json_string)
            result["source"] = "onyphe_query"
            result["raw"] = json_string
            observable.add_context(result)

        return list(links)
