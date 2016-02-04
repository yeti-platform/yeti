from pythonwhois.net import get_whois_raw
from pythonwhois.parse import parse_raw_whois
from tldextract import extract

from core.analytics import OneShotAnalytics
from core.database import Link
from core.observables import Email, Text


def link_from_contact_info(hostname, contact, field, klass, tag, description=None):
    if contact is not None and field in contact:
        node = klass.get_or_create(value=contact[field])
        link = Link.connect(hostname, node)
        link.add_history(tag=tag, description=description)

        return link
    else:
        return None


class Whois(OneShotAnalytics):

    default_values = {
        "name": "Whois",
        "description": "Perform a Whois request on the domain name and tries to"
                       " extract relevant information."
    }

    ACTS_ON = "Hostname"

    @staticmethod
        links = []
    def analyze(hostname, settings={}):

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
                    ('email', Email, 'Registrant', 'Registrant Email'),
                    ('name', Text, 'Registrant', 'Registrant Name'),
                    ('organization', Text, 'Registrant', 'Registrant Organization'),
                    ('phone', Text, 'Registrant', 'Registrant Phone Number'),
                ]

                for field, klass, tag, description in fields_to_extract:
                    link = link_from_contact_info(hostname, parsed['contacts']['registrant'], field, klass, tag, description)
                    if link is not None:
                        links.append(link)

            if should_add_context:
                hostname.add_context(context)
            else:
                hostname.save()

        return links
