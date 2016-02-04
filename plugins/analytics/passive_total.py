import requests
import json
from datetime import datetime

from core.analytics import OneShotAnalytics
from core.observables import Observable, Hostname


class PassiveTotal(OneShotAnalytics):
    default_values = {
        "name": "PassiveTotal Passive DNS",
        "description": "Perform passive DNS (reverse) lookups on domain names or IP addresses."
    }

    settings = {
        "passivetotal_api_key": {
            "name": "PassiveTotal API Key",
            "description": "API Key provided by PassiveTotal."
        }
    }

    ACTS_ON = ["Hostname", "Ip"]
    API_URL = 'https://api.passivetotal.org/api/v1/passive'

    @staticmethod
    def analyze(observable, settings):
        links = set()

        params = {
            'api_key': settings['passivetotal_api_key'],
            'query': observable.value
        }

        r = requests.get(PassiveTotal.API_URL, params=params)
        r.raise_for_status()
        result = json.loads(r.content)

        for record in result['results']['records']:
            first_seen = datetime.strptime(record['firstSeen'], "%Y-%m-%d %H:%M:%S")
            last_seen = datetime.strptime(record['lastSeen'], "%Y-%m-%d %H:%M:%S")

            new = Observable.add_text(record['resolve'])
            if isinstance(observable, Hostname):
                links.update(observable.link_to(new, "A record", 'PassiveTotal', first_seen, last_seen))
            else:
                links.update(new.link_to(observable, "A record", 'PassiveTotal', first_seen, last_seen))

        return links
