import requests


from core.config.config import yeti_config
from core.schemas.observables import ipv4, certificate
from core.schemas.observable import ObservableType
from core import taskmanager
from core.schemas import task
from core.config.config import yeti_config
from OpenSSL.crypto import FILETYPE_PEM, load_certificate
from OpenSSL.crypto import FILETYPE_ASN1, dump_certificate


class CirclPassiveSSLApi:
    API = "https://www.circl.lu/v2pssl/"
    HEADERS = {"User-Agent": "Yeti Analytics Worker", "accept": "application/json"}

    @staticmethod
    def search_ip(ip: ipv4.IPv4):
        auth = (
            yeti_config["circl_passivessl"]["username"],
            yeti_config["circl_passivessl"]["password"],
        )

        r = requests.get(
            CirclPassiveSSLApi.API + "query/" + ip.value,
            auth=auth,
            headers={
                "User-Agent": "Yeti Analytics Worker",
                "accept": "application/json",
            },
            proxies=yeti_config.get('proxy'),
        )

        if r.status_code == 200:
            return r.json()

    @staticmethod
    def fetch_cert(cert_sha1: str, settings: dict):
        auth = (
            yeti_config["circl_passivessl"]["username"],
            yeti_config["circl_passivessl"]["password"],
        )

        r = requests.get(
            CirclPassiveSSLApi.API + "cfetch/" + cert_sha1,
            auth=auth,
            headers={
                "User-Agent": "Yeti Analytics Worker",
                "accept": "application/json",
            },
            proxies=yeti_config.get('proxy'),
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

    acts_on: list[ObservableType] = [ObservableType.ipv4]

    def each(self, ip: ipv4.IPv4):
        links = set()
        results = {}

        ip_search = CirclPassiveSSLApi.search_ip(ip)
        if ip_search:
            for ip_addr, ip_details in ip_search.items():
                for cert_sha1 in ip_details.get("certificates", []):
                    cert_result = CirclPassiveSSLApi.fetch_cert(cert_sha1)
                    if cert_result:
                        _info = cert_result.get("info", {})
                        x509 = load_certificate(FILETYPE_PEM, cert_result.get("pem"))

                        der = dump_certificate(FILETYPE_ASN1, x509)

                        cert = certificate.Certificate.from_data(der)

                        cert.subject = _info.get("subject", "")

                        cert.issuer = _info.get("issuer", "")

                        cert.save()

                        ip.link_to(cert, "ip-certificate", "CirlPassiveSSL")


taskmanager.TaskManager.register_task(CirclPassiveSSLSearchIP)
