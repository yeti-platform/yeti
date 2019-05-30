import json
import requests
from core.observables import Observable
from core.analytics import OneShotAnalytics
from core.observables import Ip, Certificate, Text, Hostname, Hash, AutonomousSystem
from core.config.config import yeti_config
from core.errors import GenericYetiError, ObservableValidationError

class CensysApi(object):
    """
        https://censys.io/api
    """
    settings = {
        "urlscanio_secret": {
            "name": "censys_secret",
            "description": "Secret provided by Censys.io."
        },
        "urlscanio_api_key": {
            "name": "censys_apikey",
            "description": "API Key provided by Censys.io."
        }
    }

    API_URL = "https://censys.io/api/v1/view"

    @staticmethod
    def _process_data(json_result, observable):

        links = set()

        if isinstance(observable, Ip):
            if json_result.get('autonomous_system'):
                if json_result['autonomous_system'].get('asn'):
                    asn = AutonomousSystem.get_or_create(value=str(json_result['autonomous_system']['asn']))
                    links.update(asn.active_link_to(observable, 'asn#', 'Censys Query'))

                if json_result['autonomous_system'].get('name'):
                    asnname = Text.get_or_create(value=json_result['autonomous_system']['name'])
                    links.update(asnname.active_link_to(observable,
                        'asn_name', 'Censys Query'))

                if json_result['autonomous_system'].get('routed_prefix'):
                    routed_prefix = Text.get_or_create(value=json_result['autonomous_system']['routed_prefix'])
                    links.update(routed_prefix.active_link_to(observable,
                        'routed_prefix', 'Censys Query'))

            json_result = json_result.get("443", {}).get('https', {}).get('tls', {}).get("certificate", {})

        if not json_result.get('parsed', {}):
            return list(links)

        parsed = json_result['parsed']

        for name in parsed.get('names', []):
            #Ignore duplicated host
            if isinstance(observable, Ip) and name == observable.value:
                continue

            o_type = Observable.guess_type(name)
            new_host = o_type.get_or_create(value=name)
            links.update(
                new_host.active_link_to(observable,
                'host', 'Censys Query')
            )

        for field in ('fingerprint_md5', 'fingerprint_sha1', 'fingerprint_sha256'):
            #Ignore duplicated sha256
            if field == 'fingerprint_sha256' and isinstance(observable, Hash):
                continue

            if parsed.get(field):
                new_hash = Hash.get_or_create(value=parsed[field])
                links.update(
                    new_hash.active_link_to(observable,
                    field, 'Censys Query')
                )

            elif 'subject_dn' in parsed:
                text = Text.get_or_create(value=parsed['subject_dn'])
                links.update(text.active_link_to(observable,
                    field, 'Censys Query')
                )

        return list(links)

    @staticmethod
    def fetch(observable, settings):

        types = {
            'Ip': 'ipv4',
            'Hash': 'certificates',
            #'Hostname': 'ipv4',
            'Certificate': 'certificates',
        }

        if isinstance(observable, Hash) and len(observable.value) != 64:
            raise GenericYetiError("Only supports sha256 hash")

        try:
            url = CensysApi.API_URL+'/'+types[observable.type]+'/'+ observable.value
            response = requests.get(url, proxies=yeti_config.proxy, auth=(
                settings['censys_apikey'], settings['censys_secret']
            ))

            if not response.ok:
                raise GenericYetiError("Status code: ".format(response.status_code))

            return response.json()

        except Exception as e:
            raise GenericYetiError("Hit an error checking {},{}".format(
                observable.value, e
            ))

class CensysApiQuery(OneShotAnalytics, CensysApi):
    default_values = {
        'name': 'Censys Lookup',
        'description': 'Perform a CensysApi query.',
    }

    ACTS_ON = ['Ip', 'Cert', 'Hash']

    def analyze(self, observable, results):
        links = list()
        json_result = CensysApi.fetch(observable, results.settings)

        if json_result is not None:
            json_string = json.dumps(
                json_result, sort_keys=True, indent=4, separators=(',', ': '))
            results.update(raw=json_string)
            links = CensysApi._process_data(json_result, observable)
            context = {'raw': json_string, 'source': self.name}
            observable.add_context(context)

        return links
