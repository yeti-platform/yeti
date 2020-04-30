import json
import requests
from core.analytics import OneShotAnalytics
from core.observables import AutonomousSystem, Hostname, Ip, Text, Url
from core.config.config import yeti_config
from core.errors import GenericYetiError

class UrlScanIoApi(object):
    """
        https://urlscan.io/about-api/
    """

    API_URL = "https://urlscan.io/api/v1/search/"

    @staticmethod
    def _process_asn_data(page, observable):
        links = set()
        if page['page'].get('asn'):
            asn = AutonomousSystem.get_or_create(value=page['page']['asn'].replace("AS", ""))
            links.update(asn.active_link_to(observable, 'asn#', 'UrlScanIo Query'))

        if page['page'].get('asnname'):
            asnname = Text.get_or_create(value=page['page']['asnname'])
            links.update(asnname.active_link_to(observable,
                'asn_name', 'UrlScanIoQuerycanIo Query'))

        if page['page'].get('server'):
            server = Text.get_or_create(value=page['page']['server'])
            links.update(server.active_link_to(observable,
                'server', 'UrlScanIo Query'))

        return list(links)

    @staticmethod
    def _process_data(json_result, observable):
        links = set()

        for page in json_result:
            if not page.get("page"):
                continue

            # IP iocs has more data than the rest
            if not isinstance(observable, Ip) and page['page'].get('ip'):
                new_ip = Ip.get_or_create(value=page['page']['ip'])
                links.update(
                    new_ip.active_link_to(observable,
                        'ip', 'UrlScanIo Query')
                )

            if not isinstance(observable, Hostname) and page['page'].get('domain'):
                new_host = Hostname.get_or_create(value=page['page']['domain'])
                links.update(
                    new_host.active_link_to(observable,
                        'hostname', 'UrlScanIo Query')
                )

            if not isinstance(observable, Url) and page['page'].get('url'):
                new_url = Url.get_or_create(value=page['page']['url'])
                links.update(
                    new_url.active_link_to(observable,
                        'url', 'UrlScanIo Query')
                )

            links.update(UrlScanIoApi._process_asn_data(page, observable))

    @staticmethod
    def fetch(observable):

        types = {
            'Ip': 'ip:"{}"',
            'Hostname': 'domain:"{}"',
            'Url': 'url:"{}"',
            'Hash': 'hash:"{}"',
        }

        params = {"q": types[observable.type].format(observable.value)}
        try:
            response = requests.get(UrlScanIoApi.API_URL,
                params=params, proxies=yeti_config.proxy)
            if not response.ok:
                raise GenericYetiError("Status code: ".format(response.status_code))

            if response.json().get('total', 0) > 0:
                return response.json()['results']

            return None
        except Exception as e:
            raise GenericYetiError("Hit an error checking {},{}".format(
                observable.value, e
            ))


class UrlScanIoQuery(OneShotAnalytics, UrlScanIoApi):
    default_values = {
        'name': 'UrlScanIo',
        'description': 'Perform a UrlScanIo query.',
    }
    # 'Url', url search doesn't work right now
    ACTS_ON = ['Ip', 'Hostname', 'Hash']

    def analyze(self, observable, results):
        links = list()
        json_result = UrlScanIoApi.fetch(observable)

        if json_result is not None:
            json_string = json.dumps(
                json_result, sort_keys=True, indent=4, separators=(',', ': '))
            results.update(raw=json_string)
            links = UrlScanIoApi._process_data(json_result, observable)
            context = {'raw': json_string, 'source': self.name}
            observable.add_context(context)

        return links
