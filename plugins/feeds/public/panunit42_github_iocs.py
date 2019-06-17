import logging
from datetime import timedelta
from core.feed import Feed
from core.observables import Observable
from core.observables import Hash, Url, Hostname, Ip, MacAddress, Email
from core.observables.helpers import register_certificate, register_observables

BLACKLIST_DOMAINS = [
    'technet.microsoft.com',
    'cloudblogs.microsoft.com',
    'capec.mitre.org',
    'attack.mitre.org',
    'securelist.com',
    'blog.avast.com',
]


class PanUnit42GithubIocs(Feed):

    default_values = {
        'frequency': timedelta(hours=24),
        'name': 'PanUnit42GithubIocs',
        'source': 'https://api.github.com/repos/pan-unit42/iocs/commits',
        'description': 'Get Iocs from Pan-Unit42 GitHub Iocs repo',
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
            if content:
                content, filename = content
                self.process_content(content, filename)

    def process_content(self, content, filename):
        context = dict(source=self.name)
        context['description'] = 'File: {}'.format(filename)

        if content.startswith('Certificate:') and content.endswith(
                '-----END CERTIFICATE-----\n'):
            register_certificate(content, context, self.name)

        else:
            try:
                observables = Observable.from_string(content)
                register_observables(
                    observables, self.blacklist_domains, context, self.source)
            except Exception as e:
                logging.error(e)
                return
