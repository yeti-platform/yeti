from tldextract import extract
from core.analytics import InlineAnalytics
from core.observables import Hostname


SUSPICIOUS_TLDS = ['pw', 'cc', 'nu', 'ms', 'vg', 'cm', 'biz', 'cn', 'kr', 'br', 'ws', 'me']


class ProcessHostnames(InlineAnalytics):

    default_values = {
        "name": "ProcessHostnames",
        "description": "Extracts and analyze domains",
    }

    ACTS_ON = 'Hostname'

    @staticmethod
    def analyze_string(hostname_string):
        parts = extract(hostname_string)
        return [parts.registered_domain]

    @staticmethod
    def each(hostname):
        parts = extract(hostname.value)

        if parts.suffix in SUSPICIOUS_TLDS:
            hostname.tag('suspicious_tld')

        if parts.subdomain != '':
            hostname.update(domain=False)

            domain = Hostname.get_or_create(value=parts.registered_domain, domain=True)
            domain.add_source("analytics")
            hostname.active_link_to(domain, "domain", "ProcessHostnames", clean_old=False)

            if domain.has_tag('dyndns'):
                hostname.tag('dyndns')

            return domain
        else:
            hostname.update(domain=True)
            return None
