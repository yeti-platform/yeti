import pytz
import logging
import requests
from dateutil import parser
from datetime import datetime, timedelta
from core.feed import Feed
from core.errors import GenericYetiError
from core.observables import Observable
from core.observables import Hash, Url, Hostname, Ip, MacAddress, Email, Certificate
from core.errors import ObservableValidationError
from core.config.config import yeti_config

utc=pytz.UTC

class EsetGithubIocs(Feed):

    '''
        How github data works
        1. Retrieve data about latest commits
        2. Load commit details and process
    '''

    if hasattr(yeti_config, 'github') and yeti_config.github.token:
        token = yeti_config.github.token
        headers = {'Authorization': 'token {}'.format(token)}
    else:
        headers = {}
        #raise GenericYetiError('You need to set a github token in yeti.conf')

    default_values = {
        'frequency': timedelta(hours=24),
        'name': 'EsetGithubIocs',
        'source': 'https://api.github.com/repos/eset/malware-ioc/commits',
        'description': 'Get Iocs from Eset GitHub Iocs repo',
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

    def process_content(self, content, filename, commit_date):
        context = dict(source=self.name)
        context['description'] = 'File: {}'.format(filename)
        context['date_added'] = parser.parse(commit_date)

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
                        if key == 'Url' and not any([domain in ioc for domain in self.blacklist_domains]):
                            try:
                                ioc_data = self.refs[key].get_or_create(value=ioc)
                                ioc_data.add_context(context)
                                ioc_data.add_source(self.name)
                            except ObservableValidationError as e:
                                logging.error(e)
                            except UnicodeDecodeError as e:
                                logging.error(e)

    def update(self):
        since_last_run = utc.localize(datetime.now() - self.frequency)
        for item in self.update_json(headers = self.headers):
            if parser.parse(item['commit']['author']['date']) < since_last_run:
                break
            self.analyze(item)

    def retrieve_tree_data(self, url):
        try:
            r = requests.get(url, headers = self.headers)
            if r.ok:
                return r.json()
        except Exception as e:
            logging.error(e)

        return False

    def analyze(self, item):
        commit_info = self.retrieve_tree_data(item['url'])
        if commit_info and commit_info.get('files', []):
            for block in commit_info['files']:
                if block['filename'] in self.blacklist:
                    continue

                if 'patch' in block:
                    # load only additions
                    content = '\n'.join([line[1:] for line in block['patch'].split('\n') if line.startswith('+')])
                    self.process_content(content, block['filename'], item['commit']['author']['date'])

