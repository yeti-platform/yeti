import logging
import re
from datetime import datetime, timedelta

from dateutil import parser

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip, Observable


class CybercrimeTracker(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "CybercrimeTracker",
        "source": "http://cybercrime-tracker.net/rss.xml",
        "description": "CyberCrime Tracker - Latest 20 CnC URLS",
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        for item in self.update_xml(
                'item', ["title", "link", "pubDate", "description"]):

            pub_date = parser.parse(item['pubDate'])
            if self.last_run is not None:
                if since_last_run > pub_date:
                    continue

            self.analyze(item, pub_date)

    def analyze(self, item, pub_date):  # pylint: disable=arguments-differ
        s_re = '\[([^\]]*)] Type: (\w+) - IP: (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
        r = re.compile(s_re)
        m = r.match(item['description'])
        malware_family = ''
        c2_IP = ''
        if m:
            malware_family = m.group(2)
            c2_IP = m.group(3)

        observable = item['title']
        description = item['description'].lower()

        context = {}
        context['description'] = "{} C2 server".format(c2_IP)
        context['date_added'] = pub_date
        context['source'] = self.name

        c2 = None
        e = None

        try:
            e = Observable.add_text(observable)
            if c2_IP:
                c2 = Ip.get_or_create(value=c2_IP)
                e.active_link_to(c2, "IP", self.name, clean_old=False)

        except ObservableValidationError as e:
            logging.error(e)
            logging.error(description)
            return

        tags = ['malware', 'c2', malware_family.lower(), 'crimeware']

        if malware_family == 'pony':
            tags.extend(['stealer', 'dropper'])
        elif malware_family == 'athena':
            tags.extend(['stealer', 'ddos'])
        elif malware_family in ['zeus', 'citadel', 'lokibot']:
            tags.extend(['banker'])

        if e:
            e.add_context(context)
            e.add_source(self.name)
            e.tag(tags)

        if c2:
            c2.add_context(context)
            c2.add_source(self.name)
            c2.tag(tags)
