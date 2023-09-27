import json
import logging

import requests


from core.config.config import yeti_config
from core.schemas.observables import ipv4, certificate
from core import taskmanager
from core.schemas import task
from OpenSSL.crypto import FILETYPE_PEM, load_certificate
from OpenSSL.crypto import FILETYPE_ASN1, dump_certificate


class CirclPassiveSSLApi(object):
    settings = {
        "circl_username": {
            "name": "Circl.lu username",
            "description": "Username for Circl.lu Passive SSL API.",
        },
        "circl_password": {
            "name": "Circl.lu password",
            "description": "Password for Circl.lu Passive SSL API.",
        },
    }

    API = "https://www.circl.lu/v2pssl/"
    HEADERS = {"User-Agent": "Yeti Analytics Worker", "accept": "application/json"}

    @staticmethod
    def search_ip(ip:ipv4.IPv4, settings:dict):
        auth = (settings["circl_username"], settings["circl_password"])

        r = requests.get(
            CirclPassiveSSLApi.API + "query/" + ip.value,
            auth=auth,
            headers={
                "User-Agent": "Yeti Analytics Worker",
                "accept": "application/json",
            },
            proxies=yeti_config.proxy,
        )

        if r.status_code == 200:
            return r.json()

    @staticmethod
    def fetch_cert(cert_sha1:str, settings:dict):
        auth = (settings["circl_username"], settings["circl_password"])

        r = requests.get(
            CirclPassiveSSLApi.API + "cfetch/" + cert_sha1,
            auth=auth,
            headers={
                "User-Agent": "Yeti Analytics Worker",
                "accept": "application/json",
            },
            proxies=yeti_config.proxy,
        )

        if r.status_code == 200:
            return r.json()


class CirclPassiveSSLSearchIP(task.AnalyticsTask, CirclPassiveSSLApi):
    _defaults = {
        "name": "Circl.lu IP to ssl certificate lookup.",
        "group": "SSL Tools",
        "description": "Perform a lookup on ssl certificates \
         related to an ip address.",
    }

    ACTS_ON = ["Ip"]

    
    def each(ip:ipv4.IPv4):
        links = set()
        results = {}
        
        ip_search = CirclPassiveSSLApi.search_ip(ip, CirclPassiveSSLApi.settings)
        if ip_search:
            for ip_addr, ip_details in ip_search.items():
                for cert_sha1 in ip_details.get("certificates", []):
                    
                    cert_result = CirclPassiveSSLApi.fetch_cert(
                        cert_sha1, CirclPassiveSSLApi.settings
                    )
                    if cert_result:
                        _info = cert_result.get("info", {})
                        x509 = load_certificate(
                            FILETYPE_PEM, cert_result.get("pem")
                        )

                        der = dump_certificate(FILETYPE_ASN1, x509)

                        cert = certificate.Certificate.from_data(der)

                        cert.subject = _info.get("subject", "")
                        
                        cert.issuer =_info.get("issuer", "")
            
                        cert.save()

                        ip.link_to(cert,'ip-certificate','CirlPassiveSSL')

taskmanager.TaskManager.register_task(CirclPassiveSSLSearchIP)
