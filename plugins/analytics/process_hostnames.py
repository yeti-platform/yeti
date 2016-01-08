from datetime import timedelta
from tldextract import extract
from core.analytics import ScheduledAnalytics
from core.database import Link
from core.observables import Hostname


SUSPICIOUS_TLDS = ['pw', 'cc', 'nu', 'ms', 'vg', 'cm', 'biz', 'cn', 'kr', 'br', 'ws', 'me']


class ProcessHostnames(ScheduledAnalytics):

    settings = {
        "frequency": timedelta(seconds=10),
        "name": "ProcessHostnames",
        "description": "Extracts and analyze domains",
    }

    ACTS_ON = 'Hostname'
    EXPIRATION = None

    @staticmethod
    def analyze_string(hostname_string):
        parts = extract(hostname_string)
        return [parts.registered_domain]

    @classmethod
    def each(cls, hostname, rtype=None, results=[]):
        parts = extract(hostname.value)

        if parts.suffix in SUSPICIOUS_TLDS:
            hostname.tag('suspicious_tld')

        if parts.subdomain != '':
            hostname.update(domain=False)

            domain = Hostname.get_or_create(value=parts.registered_domain, domain=True)
            domain.add_source("analytics")
            l = Link.connect(hostname, domain)
            l.add_history(tag='domain')

            if domain.has_tag('dyndns'):
                hostname.tag('dyndns')

            return domain
        else:
            hostname.update(domain=True)
            return None
