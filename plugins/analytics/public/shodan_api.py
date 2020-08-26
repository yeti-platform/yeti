import json
import logging

import shodan

from core.analytics import OneShotAnalytics
from core.entities import Company
from core.observables import Hostname, AutonomousSystem


class ShodanApi(object):
    settings = {
        "shodan_api_key": {
            "name": "Shodan API Key",
            "description": "API Key provided by Shodan.io."
        }
    }

    @staticmethod
    def fetch(observable, api_key):
        try:
            return shodan.Shodan(api_key).host(observable.value)
        except shodan.APIError as e:
            logging.error('Error: {}'.format(e))


class ShodanQuery(OneShotAnalytics, ShodanApi):
    default_values = {
        "name": "Shodan",
        "description":
            "Perform a Shodan query on the IP address and tries to"
            " extract relevant information."
    }

    ACTS_ON = "Ip"

    @staticmethod
    def analyze(ip, results):
        links = set()
        result = ShodanApi.fetch(ip, results.settings['shodan_api_key'])
        json_string = json.dumps(
            result,
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
        results.update(raw=json_string)

        if 'tags' in result and result['tags'] is not None:
            ip.tag(result['tags'])

        if 'asn' in result and result['asn'] is not None:
            o_asn = AutonomousSystem.get_or_create(value=result['asn'].replace("AS", ""))
            links.update(o_asn.active_link_to(ip, 'asn#', 'Shodan Query'))

        if 'hostnames' in result and result['hostnames'] is not None:
            for hostname in result['hostnames']:
                h = Hostname.get_or_create(value=hostname)
                links.update(h.active_link_to(ip, 'A record', 'Shodan Query'))

        if 'isp' in result and result['isp'] is not None:
            o_isp = Company.get_or_create(name=result['isp'])
            links.update(ip.active_link_to(o_isp, 'hosting', 'Shodan Query'))

        for context in ip.context:
            if context['source'] == 'shodan_query':
                break
        else:
            # Remove the data part (Shodan Crawler Data, etc.)
            result.pop("data", None)

            result['source'] = 'shodan_query'
            ip.add_context(result)

        return list(links)
