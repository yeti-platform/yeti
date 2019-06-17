import logging
from datetime import timedelta
from core.feed import Feed
from core.observables import Observable
from core.observables import Hash, Url, Hostname, Ip, MacAddress, Email
from core.observables.helpers import register_certificate, register_observables


class VitaliKremezGitHub(Feed):

    default_values = {
        'frequency': timedelta(hours=24),
        'name': 'VitaliKremezGitHub',
        'source': 'https://api.github.com/repos/k-vitali/Malware-Misc-RE/commits', # pylint: disable=line-too-long
        'description': 'Get Iocs from Vitaly Kremez GitHub repo',
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
    blacklist_domains = (
        'technet.microsoft.com',
        'cloudblogs.microsoft.com',
        'capec.mitre.org',
        'attack.mitre.org',
    )

    def update(self):
        for content in self.update_github():
            if not content:
                continue

            content, filename = content
            self.process_content(content, filename)

    # pylint: disable=arguments-differ
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
                    self.refs,
                    observables,
                    self.blacklist_domains,
                    context,
                    self.source,
                )
            except Exception as e:
                logging.error(e)
                return
