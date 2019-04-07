import json
import logging

import requests

from core.analytics import OneShotAnalytics
from core.config.config import yeti_config
from core.observables import Certificate, CertificateSubject, Ip
from OpenSSL.crypto import FILETYPE_PEM, load_certificate
from OpenSSL.crypto import FILETYPE_ASN1, dump_certificate


class CirclPassiveSSLApi(object):
    settings = {
        'circl_username': {
            'name': 'Circl.lu username',
            'description': 'Username for Circl.lu Passive SSL API.'
        },
        'circl_password': {
            'name': 'Circl.lu password',
            'description': 'Password for Circl.lu Passive SSL API.'
        }
    }

    API = 'https://www.circl.lu/v2pssl/'
    HEADERS = {'User-Agent': 'Yeti Analytics Worker',
               'accept': 'application/json'}

    @staticmethod
    def search_ip(observable, settings):
        auth = (
            settings['circl_username'],
            settings['circl_password']
        )

        if isinstance(observable, Ip):
            r = requests.get(CirclPassiveSSLApi.API + 'query/' +
                             observable.value, auth=auth,
                             headers={
                                 'User-Agent': 'Yeti Analytics Worker',
                                 'accept': 'application/json'
                             },
                             proxies=yeti_config.proxy)

            if r.ok:
                return r.json()

    @staticmethod
    def fetch_cert(cert_sha1, settings):
        auth = (
            settings['circl_username'],
            settings['circl_password']
        )

        r = requests.get(CirclPassiveSSLApi.API + 'cfetch/' + cert_sha1,
                         auth=auth,
                         headers={
                             'User-Agent': 'Yeti Analytics Worker',
                             'accept': 'application/json'
                         },
                         proxies=yeti_config.proxy)

        if r.ok:
            return r.json()


class CirclPassiveSSLSearchIP(OneShotAnalytics, CirclPassiveSSLApi):
    default_values = {
        'name': 'Circl.lu IP to ssl certificate lookup.',
        'group': 'SSL Tools',
        'description': 'Perform a lookup on ssl certificates \
         related to an ip address.'
    }

    ACTS_ON = ['Ip']

    @staticmethod
    def analyze(observable, results):
        links = set()

        if isinstance(observable, Ip):
            ip_search = CirclPassiveSSLApi.search_ip(
                observable, results.settings)
            if ip_search:
                json_string = json.dumps(
                    ip_search, sort_keys=True, indent=4,
                    separators=(',', ': '))

                results.update(raw=json_string)

                for ip_addr, ip_details in ip_search.items():
                    for cert_sha1 in ip_details.get('certificates', []):
                        try:
                            cert_result = CirclPassiveSSLApi.fetch_cert(
                                cert_sha1, results.settings)
                            if cert_result:
                                _info = cert_result.get('info', {})
                                x509 = load_certificate(
                                    FILETYPE_PEM, cert_result.get('pem'))

                                DER = dump_certificate(FILETYPE_ASN1, x509)

                                cert_ob = Certificate.from_data(
                                    data=DER)

                                subject = CertificateSubject.get_or_create(
                                    value=_info.get('subject', ''))

                                issuer = CertificateSubject.get_or_create(
                                    value=_info.get('issuer', ''))

                                links.update(observable.active_link_to(
                                    cert_ob,
                                    'cert_details',
                                    'circl_passive_ssl_query'))

                                links.update(cert_ob.active_link_to(
                                    subject,
                                    'subject',
                                    'circl_passive_ssl_query'))

                                links.update(cert_ob.active_link_to(
                                    issuer,
                                    'issuer',
                                    'circl_passive_ssl_query'))

                        except Exception as e:
                            logging.error(
                                'Error attempting to fetch cert file {}'.
                                format(e))

        return list(links)
