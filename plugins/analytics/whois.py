from pythonwhois.net import get_whois_raw
from pythonwhois.parse import parse_raw_whois
from tldextract import extract

from core.analytics import OneShotAnalytics
from core.database import Link
from core.observables import Email, Text


def link_from_contact_info(hostname, contact, field, klass, description):
    if contact is not None and field in contact:
        node = klass.get_or_create(value=contact[field])

        return hostname.active_link_to(node, description, 'Whois')
    else:
        return ()


class Whois(OneShotAnalytics):

    default_values = {
        "name": "Whois",
        "description": "Perform a Whois request on the domain name and tries to"
                       " extract relevant information."
    }

    ACTS_ON = "Hostname"

    @staticmethod
    def analyze(hostname, settings={}):
        links = set()

        parts = extract(hostname.value)

        if parts.subdomain == '':
            should_add_context = False
            for context in hostname.context:
                if context['source'] == 'Whois':
                    break
            else:
                should_add_context = True
                context = {'source': 'Whois'}

            data = get_whois_raw(hostname.value)
            parsed = parse_raw_whois(data, normalized=True)
            context['raw'] = data[0]

            if 'creation_date' in parsed:
                context['creation_date'] = parsed['creation_date'][0]
            if 'registrant' in parsed['contacts']:
                fields_to_extract = [
                    ('email', Email, 'Registrant Email'),
                    ('name', Text, 'Registrant Name'),
                    ('organization', Text, 'Registrant Organization'),
                    ('phone', Text, 'Registrant Phone Number'),
                ]

                for field, klass, description in fields_to_extract:
                    links.update(link_from_contact_info(hostname, parsed['contacts']['registrant'], field, klass, description))

            if should_add_context:
                hostname.add_context(context)
            else:
                hostname.save()

        return list(links)
