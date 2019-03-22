import json
import logging
import requests
from datetime import datetime
from core.analytics import OneShotAnalytics
from core.observables import Observable, Ip, Hash, Text
from core.config.config import yeti_config


class CirclPassiveSSLApi(object):
    settings = {
        "circl_username": {
            "name": "Circl.lu username",
            "description": "Username for Circl.lu API."
        },
        "circl_password": {
            "name": "Circl.lu password",
            "description": "Password for Circl.lu API."
        }
    }

    @staticmethod
    def search_ip(observable, settings):
        auth = (
            settings["circl_username"],
            settings["circl_password"]
        )

        API_URL = "https://www.circl.lu/v2pssl/"
        headers = {'accept': 'application/json'}

        if isinstance(observable, Ip):
   	        r = requests.get(API_URL + "query/" + observable.value, auth=auth , headers=headers, proxies=yeti_config.proxy)
            	if r.ok:
                	return r.json()

        return False

    @staticmethod
    def search_cert_sha1(observable, settings):
        auth = (
            settings["circl_username"],
            settings["circl_password"]
        )

        API_URL = "https://www.circl.lu/v2pssl/"
        headers = {'accept': 'application/json'}

        if isinstance(observable, Hash): 
       	    r = requests.get(API_URL + "cquery/" + observable.value, auth=auth , headers=headers, proxies=yeti_config.proxy)
            if r.ok:
                return r.json()

        return False

    @staticmethod
    def fetch_cert(observable, settings):
        auth = (
            settings["circl_username"],
            settings["circl_password"]
        )

        API_URL = "https://www.circl.lu/v2pssl/"
        headers = {'accept': 'application/json'}
        
        if isinstance(observable, Hash): 
       	    r = requests.get(API_URL + "cfetch/" + observable.value, auth=auth , headers=headers, proxies=yeti_config.proxy)
            if r.ok:
                return r.json()

        return False

class CirclPassiveSSLSearchIP(OneShotAnalytics, CirclPassiveSSLApi):
    default_values = {
        "name": "Circl.lu search IP for ssl certificate",
        "group": "SSL Tools",
        "description": "Perform passive ssl lookups on ssl hash or ip address."
    }

    ACTS_ON = ["Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        if isinstance(observable, Ip):
            json_result = CirclPassiveSSLApi.search_ip(observable, results.settings)

            json_string = json.dumps(
                json_result, sort_keys=True, indent=4, separators=(',', ': '))
            results.update(raw=json_string)

            result = {}
            result['source'] = 'circl_passive_ssl_query'
            result['raw'] = json_string

            if json_result:
                for k,v in json_result.items():
                    if k == observable.value:
                        for cert_hash, cert_details in v.get("subjects", {}).items():
                            sha1 = Hash.get_or_create(value=cert_hash)
                            links.update(observable.active_link_to(
                                sha1, 'ip_linked_to_ssl_fingerprint', 'circl_passive_ssl_query')
                            )

                            for value in cert_details.get("values", []):
                                new_text_node = Text.get_or_create(value=value)
                                links.update(
                                    observable.active_link_to(new_text_node, "SSL Cert Details", "circl_passive_ssl_query")
                                )

            observable.add_context(result)
        return list(links)


class CirclPassiveSSLSearchSha1(OneShotAnalytics, CirclPassiveSSLApi):
    default_values = {
        "name": "Circl.lu search Sha1 hash of a certificate for related IP addresses",
        "group" : "SSL Tools",
        "description": "Perform passive ssl lookups on ssl hash or ip address."
    }

    ACTS_ON = ["Hash"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        if isinstance(observable, Hash):
            json_result = CirclPassiveSSLApi.search_cert_sha1(observable, results.settings)
            result = {}
            result['source'] = 'circl_passive_ssl_query'
            if json_result:
  	            results.update(raw= json.dumps( { "hits" : str(json_result.get("hits", "0")) }) )
                for ip in json_result.get("seen", []):
                    o_ip = Ip.get_or_create(value=ip)
                    links.update(observable.active_link_to(
                        o_ip, 'cert_linked_to_ip', 'circl_passive_ssl_query'))
            observable.add_context(result)
        return list(links)


class CirclPassiveSSLFetchCertFile(OneShotAnalytics, CirclPassiveSSLApi):
    default_values = {
        "name": "Circl.lu fetch certificate file",
        "group" : "SSL Tools",
        "description": "Fetch SSL certificate file based on a sha1 hash"
    }

    ACTS_ON = ["Hash"]

    @staticmethod
    def analyze(observable, results):
        if isinstance(observable, Hash):
            links = set()
            json_result = CirclPassiveSSLApi.fetch_cert(observable, results.settings)
            json_string = json.dumps(
                json_result.get("info", {}), sort_keys=True, indent=4, separators=(',', ': '))
            results.update(raw=json_string)
            result = {}
            result['source'] = 'circl_passive_ssl_query'
            result['raw'] = json_string
            observable.add_context(result)
        return list(links)







