import logging
from datetime import timedelta
from core.feed import Feed
from core.observables import Observable
from core.observables import Hash, Url, Hostname, Ip, MacAddress, Email
from core.observables.utils import reg_certificate, reg_observables


class FireHolGitHub(Feed):

    default_values = {
        'frequency': timedelta(hours=24),
        'name': 'FireHolGitHub',
        'source': 'https://api.github.com/repos/firehol/blocklist-ipsets/commits',
        'description': 'Get Iocs from FireHol repo',
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

    blacklist = ('.gitignore', 'LICENSE', 'README.adoc', 'README-EDIT.md', 'README.md')
    blacklist_domains = (
        'technet.microsoft.com', 'cloudblogs.microsoft.com', 'capec.mitre.org',
        'attack.mitre.org', 'securelist.com', 'blog.avast.com', 'firehol.org',
        'gist.githubusercontent.com', 'www.binarydefense.com', 'www.badips.com')


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
