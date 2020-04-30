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

    def __init__(self, api_key, version='v1'):
        self.api_key = api_key
        self.base_url = 'https://www.onyphe.io/api/'
        self.version = version
        self._session = requests.Session()

        self.methods = {
            'get': self._session.get,
            'post': self._session.post,
        }

    def _choose_url(self, uri):
        self.url = urljoin(self.base_url, uri)

    def _request(self, method, payload):

        data = None

        try:
            response = self.methods[method](self.url, params=payload)
        except:
            raise APIError('Unable to connect to Onyphe')

        if response.status_code == requests.codes.NOT_FOUND:

            raise APIError('Page Not found %s' % self.url)
        elif response.status_code == requests.codes.FORBIDDEN:
            raise APIError('Access Forbidden')
        elif response.status_code == requests.codes.too_many_requests:
            raise APIError('Too Many Requests')
        elif response.status_code != requests.codes.OK:
            try:
                error = response.json()['message']
            except Exception:
                error = 'Invalid API key'

            raise APIError(error)
        try:

            data = response.json()

        except:
            raise APIError('Unable to parse JSON')

        return data

    def _prepare_request(self, uri, **kwargs):
        payload = {
            'apikey': self.api_key
        }

        if 'page' in kwargs:
            payload['page'] = kwargs['page']

        self._choose_url(uri)

        data = self._request('get', payload)
        if data:
            return data

    def _search(self,query, endpoint, **kwargs):
        return self._prepare_request(quote('/'.join([self.version, 'search',
                                               endpoint, query])), **kwargs)

    def synscan(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/synscan/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of the search about synscans.
        """
        return self._prepare_request('/'.join([self.version, 'synscan', ip]))

    def pastries(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/pastries/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of the search in pasties recorded by the service.
        """
        return self._prepare_request('/'.join([self.version, 'pastries', ip]))

    def myip(self):
        """Call API Onyphe https://www.onyphe.io/api/v1/myip

                :returns: dict -- a dictionary containing the results of myip
        """
        return self._prepare_request('/'.join([self.version, 'myip']))

    def user(self):
        """Call API Onyphe https://www.onyphe.io/api/v1/user

                :returns: dict -- a dictionary containing the results of user
        """
        return self._prepare_request('/'.join([self.version, 'user']))

    def geoloc(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/geoloc/<IP>

                :param ip: str IPv4 or IPv6 address
                :type ip: str
                :returns: dict -- a dictionary containing the results of geolocation of IP
        """
        return self._prepare_request('/'.join([self.version, 'geoloc', ip]))

    def inetnum(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/inetnum/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of inetnum of IP
        """
        return self._prepare_request('/'.join([self.version, 'inetnum', ip]))

    def threatlist(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/threatlist/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of the IP in threatlists
        """
        return self._prepare_request('/'.join([self.version, 'threatlist', ip]))

    def forward(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/forward/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the results of forward of IP
        """
        return self._prepare_request('/'.join([self.version, 'forward', ip]))

    def reverse(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/reverse/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing the domains of reverse DNS of IP
        """
        return self._prepare_request('/'.join([self.version, 'reverse', ip]))

    def ip(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/ip/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing all informations of IP
        """
        return self._prepare_request('/'.join([self.version, 'ip', ip]))

    def datascan(self, data):
        """Call API Onyphe https://www.onyphe.io/api/v1/datascan/<IP>

            :param data: IPv4/IPv6 address
            :type data: str
            :returns: dict -- a dictionary containing Information scan on IP or string
        """
        return self._prepare_request('/'.join([self.version, 'datascan', data]))

    def onionscan(self, onion):
        """Call API Onyphe https://www.onyphe.io/api/v1/onionscan/<ONION>

            :param onion: onion address
            :type onion: str
            :returns: dict -- a dictionary containing all information of onion site
        """
        return self._prepare_request('/'.join([self.version, 'onionscan', onion]))

    def ctl(self, domain):
        """Call API Onyphe https://www.onyphe.io/api/v1/ctl/<DOMAIN>

            :param domain: domain name
            :type domain: str
            :returns: dict -- a dictionary containing all informations of domain name certificates
        """
        return self._prepare_request('/'.join([self.version, 'ctl', domain]))

    def sniffer(self, ip):
        """Call API Onyphe https://www.onyphe.io/api/v1/sniffer/<IP>

            :param ip: str IPv4 or IPv6 address
            :type ip: str
            :returns: dict -- a dictionary containing all informations of IP
        """
        return self._prepare_request('/'.join([self.version, 'sniffer', ip]))

    def md5(self, md5):
        """Call API Onyphe https://www.onyphe.io/api/v1/md5/<MD5>

            :param md5: md5 hash
            :type md5: str
            :returns: dict -- a dictionary containing all informations of md5 hash
        """
        return self._prepare_request('/'.join([self.version, 'md5', md5]))

    def search_datascan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/datascan/<query>
        :param query: example product:Apache port:443 os:Windows.
        :type: str
        :return: dict -- a dictionary with result
        """

        return self._search(query, 'datascan', **kwargs)

    def search_synscan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/syscan/<query>
        :param query: example ip:46.105.48.0/21 os:Linux port:23.
        :type: str
        :return: dict -- a dictionary with result
        """
        return self._search(query, 'synscan', **kwargs)

    def search_inetnum(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/inetnum/<query>
        :param query: example organization:"OVH SAS"
        :type: str
        :return: dict -- a dictionary with result
        """
        return self._search(query, 'inetnum', **kwargs)

    def search_threatlist(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/threatlist/<query>
        :param query: example: country:RU or ip:94.253.102.185
        :type: str
        :return: dict -- a dictionary with result
        """
        return self._search(query, 'threatlist', **kwargs)

    def search_pastries(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/pastries/<query>
        :param query: example: domain:amazonaws.com or ip:94.253.102.185
        :type: str
        :return: dict -- a dictionary with result
        """
        return self._search(query, 'pastries', **kwargs)

    def search_resolver(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/resolver/<query>
                :param query: example: domain:amazonaws.com
                :type: str
                :return: dict -- a dictionary with result
                """
        return self._search(query, 'resolver', **kwargs)

    def search_sniffer(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/sniffer/<query>
                :param query: example: ip:14.164.0.0/14
                :type: str
                :return: dict -- a dictionary with result
                """
        return self._search(query, 'sniffer', **kwargs)

    def search_ctl(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/ctl/<query>
                :param query: example: host:vpn
                :type: str
                :return: dict -- a dictionary with result
                """
        return self._search(query, 'ctl', **kwargs)

    def search_onionscan(self, query, **kwargs):
        """Call API Onyphe https://www.onyphe.io/api/v1/search/onionscan/<query>
                :param query: example: data:market
                :type: str
                :return: dict -- a dictionary with result
                """
        return self._search(query, 'onionscan', **kwargs)



class OnypheAPI(object):
    """Base class for querying the Onyphe API."""

    settings = {
        'onyphe_api_key': {
            'name': 'Onyphe API Key',
            'description': 'API Key provided by onyphe.io'
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
        'name': 'Onyphe',
        'description': 'Perform a Onyphe query.',
    }

    ACTS_ON = ['Ip', 'Hostname']

    @staticmethod
    def analyze(observable, results):
        links = set()
        on_client = Onyphe(results.settings['onyphe_api_key'])
        json_result = OnypheAPI.fetch(on_client, observable)

        if json_result:
            result = {}
            json_string = json.dumps(json_result, sort_keys=True, indent=4, separators=(',', ': ') )
            results.update(raw=json_string)
            result['source'] = 'onyphe_query'
            result['raw'] = json_string
            observable.add_context(result)

        return list(links)
