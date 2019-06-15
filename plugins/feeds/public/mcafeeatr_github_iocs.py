import logging
from datetime import timedelta
from core.feed import Feed
from core.observables import Observable
from core.observables import Hash, Url, Hostname, Ip, MacAddress, Email
from core.observables.utils import register_certificate, register_observables


BLACKLIST_DOMAINS = [
    'technet.microsoft.com',
    'cloudblogs.microsoft.com',
    'capec.mitre.org',
    'attack.mitre.org',
    'securelist.com',
    'blog.avast.com',
]

class McAfeeATRGithubIocs(Feed):

    default_values = {
        'frequency': timedelta(hours=24),
        'name': 'McAfeeATRGithubIocs',
        'source': 'https://api.github.com/repos/advanced-threat-research/IOCs/commits',
        'description': 'Get Iocs from McAfee ATR GitHub Iocs repo',
    }
    refs = {
        'MacAddress': MacAddress,
        'Hash': Hash,
        'Url': Url,
        'Ip': Ip,
        'FileHash-SHA1': Hash,
        'Hostname': Hostname,
        'Email': Email,
    }

    blacklist = ('Makefile', 'LICENSE', 'README.adoc')

    def update(self):
        for content in self.update_github():
            if not content:
                continue

            content, filename = content
            self.process_content(content, filename)

    def process_content(self, content, filename):
        context = dict(source=self.name)
        context['description'] = 'File: {}'.format(filename)

        if content.startswith('Certificate:') and content.endswith(
                '-----END CERTIFICATE-----\n'):
            reg_certificate(content, context, self.name)

        else:
            try:
                observables = Observable.from_string(content)
                reg_observables(
                    observables, self.blacklist_domains, context, self.source)
            except Exception as e:
                logging.error(e)
                return
