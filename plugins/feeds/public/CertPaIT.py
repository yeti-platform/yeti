import re
import logging
from datetime import datetime, timedelta
from dateutil import parser
from core.observables import Hash
from core.feed import Feed
from core.errors import ObservableValidationError

class CertPaIT(Feed):

    default_values = {
        'frequency': timedelta(minutes=30),
        'name': 'CertPaIT',
        'source' : 'https://infosec.cert-pa.it/analyze/submission.rss',
        'description': 'This feed contains data from infosec.cert-pa.it',
    }

    regexes = (
        re.compile(r"IsDLL: (?P<isdll>\w+)"),
        re.compile(r"Packers: (?P<packers>\w+)"),
        re.compile(r"AntiDBG: (?P<antidbg>\w+)"),
        re.compile(r"AntiVM: (?P<antivm>\w+)"),
        re.compile(r"Signed: (?P<signed>\w+)"),
        re.compile(r"XOR: (?P<xor>\w+)"),
    )

    re_generic_details = re.compile('<p>Filename: <b>(?P<filename>.*)\\</b\\><br>Filetype: (?P<filetype>.*)</p>')

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        for item in self.update_xml('item', ['title', 'link', 'pubDate', 'description']):
            pubDate = parser.parse(item['pubDate'])
            if self.last_run is not None:
                if since_last_run > pubDate.utcnow():
                    return

            self.analyze(item, pubDate)

    def analyze(self, item, pubDate):
        md5 = item['title'].replace('MD5: ', '')
        context = {}
        context['date_added'] = pubDate
        context['source'] = self.name
        context['url'] = item['link']

        matched = self.re_generic_details.match(item['description'])
        if matched:
            context.update(matched.groupdict())

        for regex_compiled in self.regexes:
            matched = regex_compiled.search(item['description'])
            if matched:
                context.update(matched.groupdict())

        try:
            if md5:
                hash_data = Hash.get_or_create(value=md5)
                hash_data.add_context(context)
                hash_data.add_source(self.name)

        except ObservableValidationError as e:
            logging.error(e)
