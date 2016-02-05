from pprint import pformat
from ipwhois import IPWhois
from core.analytics import OneShotAnalytics
from core.entities import Company
from core.observables import Email


class NetworkWhois(OneShotAnalytics):

    default_values = {
        "name": "NetworkWhois",
        "description": "Perform a Network Whois request on the IP address and tries to"
                       " extract relevant information."

    }

    ACTS_ON = "Ip"

    @staticmethod
    def analyze(ip, results):
        links = set()

        r = IPWhois(ip.value)
        r = r.lookup_rdap()
        results.update(raw=pformat(r))

        for entity in r['objects']:
            entity = r['objects'][entity]
            if entity['contact']['kind'] != 'individual':
                # Create the company
                company = Company.get_or_create(name=entity['contact']['name'], rdap=entity)
                links.update(ip.active_link_to(company, 'hosting', 'Network Whois'))

                # Link it to every email address referenced
                if entity['contact']['email']:
                    for email_info in entity['contact']['email']:
                        email = Email.get_or_create(value=email_info['value'])
                        links.update(company.link_to(email, None, 'Network Whois'))

        return list(links)
