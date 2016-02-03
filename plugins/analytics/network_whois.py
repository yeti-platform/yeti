from ipwhois import IPWhois
from core.analytics import OneShotAnalytics
from core.database import Link
from core.entities import Company
from core.observables import Email, Text


class NetworkWhois(OneShotAnalytics):

    default_values = {
        "name": "NetworkWhois",
        "description": "Perform a Network Whois request on the IP address and tries to"
                       " extract relevant information."

    }

    ACTS_ON = "Ip"

    @staticmethod
    def analyze(ip):
        links = []

        results = IPWhois(ip.value)
        results = results.lookup_rdap()

        for entity in results['objects']:
            entity = results['objects'][entity]
            if entity['contact']['kind'] != 'individual':
                # Create the company
                company = Company.get_or_create(name=entity['contact']['name'], rdap=entity)
                link = Link.connect(ip, company)
                link.add_history('hosting')
                links.append(link)

                # Link it to every email address referenced
                for email_info in entity['contact']['email']:
                    email = Email.get_or_create(value=email_info['value'])
                    link = Link.connect(company, email)
                    links.append(link)

        return links
