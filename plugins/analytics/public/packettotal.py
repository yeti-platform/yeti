import logging

import requests

from core.analytics import OneShotAnalytics
from core.config.config import yeti_config
from core.observables import Hostname, Ip, Text


class PacketTotalAPI(object):
    """Base class for querying the PacketTotal API."""
    settings = {
        'packettotal_api_key': {
            'name': 'PacketTotal API Key',
            'description': 'API Key provided by packettotal.com'
        }
    }

    API = 'https://api.packettotal.com/v1/'

    @staticmethod
    def search(observable, api_key):
        # """
        # param observable: The extended observable class
        # param api_key: The api key obtained from PacketTotal
        # return  packettotal json response or None if error
        # """

        params = {'query': observable.value}

        try:
            res = requests.get(
                '{}search'.format(PacketTotalAPI.API),
                headers={'x-api-key': api_key},
                params=params,
                proxies=yeti_config.proxy
            )

            if res.ok:
                return res.json()

        except Exception as e:
            logging.error(
                'Exception while retreiving packettotal report {}'.
                format(e.message))

    @staticmethod
    def fetch_analysis(pcap_id, api_key):
        # """
        # param observable: The extended observable class
        # param api_key: The api key obtained from PacketTotal
        # return:  packettotal json response or None if error
        # """

        try:
            res = requests.get(
                '{}pcaps/{}/analysis'.format(PacketTotalAPI.API, pcap_id),
                headers={'x-api-key': api_key},
                verify=False,
                proxies=yeti_config.proxy
            )

            if res.ok:
                return res.json()

        except Exception as e:
            logging.error(
                'Exception while retreiving packettotal report {}'
                .format(e.message))


class PacketTotalQuery(PacketTotalAPI, OneShotAnalytics):
    default_values = {
        'name': 'PacketTotal',
        'description': 'Perform a PacketTotal query.',
    }

    ACTS_ON = ['Ip', 'Hostname', 'Hash', 'Url']

    @staticmethod
    def analyze(observable, results):
        links = set()
        pcap_hits = PacketTotalAPI.search(
            observable, results.settings['packettotal_api_key'])

        result = {}

        if not pcap_hits:
            return []
        for hit in pcap_hits.get('results'):
            pcap_id = hit.get('id', '')
            pcap_analysis = PacketTotalAPI.fetch_analysis(
                pcap_id, results.settings['packettotal_api_key']
            )

            if not pcap_analysis:
                return
            analysis_url = Text.get_or_create(
                value='https://packettotal.com/app/analysis?id={pcap_id}'
                .format(pcap_id=pcap_id)
            )

            links.update(
                observable.active_link_to(
                    analysis_url, 'analysis_link', 'packettotal_query')
                )

                analysis = pcap_analysis.get('analysis_summary', {})

                for signature in analysis.get('signatures', []):
                    o_sig = Text.get_or_create(value=signature)
                    links.update(
                        analysis_url.active_link_to(
                            o_sig,
                            'triggered_ids_signature',
                            'packettotal_query'
                        )
                    )

                destination_addresses = analysis.get(
                    'top_talkers', {}).get('destination_ips', {})

                for dst_addr, percentage in destination_addresses.items():
                    try:
                        o_ip = Ip.get_or_create(value=dst_addr)
                        links.update(
                            analysis_url.active_link_to(
                                o_ip,
                                'potentially_related_ip',
                                'packettotal_query'
                            )
                        )
                    except Exception as e:
                        logging.error(
                            'Error attempting to create IP {}'
                            .format(e.message))

                dns_queries = analysis.get(
                    'dns_statistics', {}).get('queries', {})

                for dns_query, percentage in dns_queries.items():
                    try:
                        o_hostname = Hostname.get_or_create(
                            value=dns_query)
                        links.update(
                            analysis_url.active_link_to(
                                o_hostname,
                                'potentially_related_hostname',
                                'packettotal_query'
                            )
                        )
                    except Exception as e:
                        logging.error(
                            'Error attempting to create hostname {}'
                            .format(e.message))

        result['source'] = 'packettotal_query'
        observable.add_context(result)

        return list(links)
