import re
import logging
from datetime import datetime, timedelta
from dateutil import parser
from core.observables import Hash
from core.feed import Feed
from core.errors import ObservableValidationError

class CertPaIt(Feed):

    default_values = {
        'frequency': timedelta(minutes=30),
        'name': 'CertPaIT',
        'source' : 'https://infosec.cert-pa.it/analyze/submission.rss',
        'description': 'This feed contains data from infosec.cert-pa.it',
    }

    regex = '<p>Filename: <b>(?P<filename>.*)\\</b\\><br>Filetype: (?P<filetype>.*)</p>\n\t+<ul>\n\t+<li>IsDLL: (?P<isdll>[\\w]+)</li>\n\t\t\t\t\t\t\t\t\t<li>Packers: (?P<packers>[\\w]+)</li>\n\t\t\t\t\t\t\t\t\t<li>AntiDBG: (?P<antidbg>[\\w]+)</li>\n\t\t\t\t\t\t\t\t\t<li>AntiVM: (?P<antivm>[\\w]+)</li>\n\t\t\t\t\t\t\t\t\t<li>Signed: (?P<signed>[\\w]+)</li>\n\t\t\t\t\t\t\t\t\t<li>XOR: (?P<xored>[\\w]+)</li>\n\t\t\t\t\t\t\t\t</ul>'

    def update(self):
        for item in self.update_xml('item', ['title', 'link', 'pubDate', 'description']):
            self.analyze(item)

    def analyze(self, item):
        md5 = item['title'].replace('MD5: ', '')
        context = {}
        context['date_added'] = parser.parse(item['pubDate'])
        context['source'] = self.name
        context['url'] = item['link']
        matched = re.match(self.regex, item['description'])
        if matched:
            context.update(matched.groupdict())

        try:
            if md5:
                hash_data = Hash.get_or_create(value=md5)
                if hash_data.new is True or self.name not in hash_data.sources:
                    hash_data.add_context(context)
                    hash_data.add_source(self.name)

        except ObservableValidationError as e:
            logging.error(e)
