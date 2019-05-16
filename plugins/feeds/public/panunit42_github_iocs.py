import logging
from dateutil import parser
from datetime import datetime, timedelta
from core.feed import Feed
from core.errors import GenericYetiError
from core.observables import Observable
from core.observables import Hash, Url, Hostname, Ip, MacAddress, Email, Certificate
from core.errors import ObservableValidationError
from core.config.config import yeti_config

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
    blacklist_domains = ('technet.microsoft.com', 'cloudblogs.microsoft.com', 'capec.mitre.org',  'attack.mitre.org', 'securelist.com', 'blog.avast.com')

    def process_content(self, content, filename):
        context = dict(source=self.name)
        context['description'] = 'File: {}'.format(filename)

        if content.startswith('Certificate:') and content.endswith('-----END CERTIFICATE-----\n'):
            #ToDo cert support
            return
            try:
                cert_data = Certificate.get_or_create(value=content)
                cert_data.add_context(context)
                cert_data.add_source(self.name)
            except ObservableValidationError as e:
                logging.error(e)
        else:
            try:
                observables = Observable.from_string(content)
            except Exception as e:
                logging.error(e)
                return

            if observables:
                for key in observables:
                    for ioc in filter(None, observables[key]):
                        if key == 'Url' and  any([domain in ioc for domain in self.blacklist_domains]):
                            continue
                        try:
                            ioc_data = self.refs[key].get_or_create(value=ioc)
                            ioc_data.add_context(context)
                            ioc_data.add_source(self.name)
                        except ObservableValidationError as e:
                             logging.error(e)
                        except UnicodeDecodeError as e:
                            logging.error(e)

    def update(self):
        for content in self.update_github():
            if content:
                content, filename = content
                self.process_content(content, filename)

