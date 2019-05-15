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
from base64 import b64decode
from core.config.config import yeti_config

utc=pytz.UTC

class EsetGithubIocs(Feed):

    '''
        How github data works
        1. Retrieve data about latest commits
        2. Get urls for changed files
        3. Load changed content
    '''

    if yeti_config.github.token:
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

    #Root path files
    blacklist = ('Makefile', 'LICENSE', 'README.adoc')
    blacklist_domains = ('technet.microsoft.com', 'cloudblogs.microsoft.com', 'capec.mitre.org',  'attack.mitre.org', 'securelist.com', 'blog.avast.com')

    def process_content(self, content, block):
        context = dict(source=self.name)
        context['description'] = 'File: {}'.format(block['path'])
        context['date_added'] = parser.parse(self.commit_info['commit']['author']['date'])


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
            self.commit_info = item
            if parser.parse(item['commit']['author']['date']) < since_last_run:
                break
            commit_details = self.retrieve_tree_data(item['commit']['tree']['url'])
            self.analyze(commit_details)

    def retrieve_tree_data(self, url):
        try:
            r = requests.get(url, headers = self.headers)
            if r.ok:
                return r.json()
        except Exception as e:
            logging.error(e)

        return False

    def analyze(self, commit_info):
        if commit_info:
            for block in commit_info.get('tree', []):
                if block['path'] in self.blacklist:
                    continue
                data = self.retrieve_tree_data(block['url'])

                if data:
                    if 'tree' in data:
                        self.analyze(data)
                    if data.get('encoding', '') == 'base64':
                        content = b64decode(data['content'])
                        self.process_content(content, block)
                    else:
                        logging.error('Add support for encoding: {} - {}'.format(data.get('encoding', 'Encoding missed'), block['url']))

