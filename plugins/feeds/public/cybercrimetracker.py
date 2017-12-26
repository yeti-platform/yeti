from datetime import datetime, timedelta
import logging

from dateutil import parser

from core.observables import Observable
from core.feed import Feed
from core.errors import ObservableValidationError


class CybercrimeTracker(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "CybercrimeTracker",
        "source": "http://cybercrime-tracker.net/rss.xml",
        "description": "CyberCrime Tracker - Latest 20 CnC URLS",
    }

    def update(self):
        for item in self.update_xml(
                'item', ["title", "link", "pubDate", "description"]):
            self.analyze(item)

    def analyze(self, item):
        observable = item['title']
        description = item['description'].lower()
        context = {}
        context['description'] = "{} C2 server".format(description)
        context['date_added'] = parser.parse(item['pubDate'])
        context['source'] = self.name

        try:
            e = Observable.add_text(observable)
        except ObservableValidationError as e:
            logging.error(e)
            return

        e.add_context(context)
        e.add_source("feed")

        tags = ['malware', 'c2', description, 'crimeware']
        if description == 'pony':
            tags.extend(['stealer', 'dropper'])
        elif description == 'athena':
            tags.extend(['stealer', 'ddos'])
        elif description in ['zeus', 'citadel']:
            tags.extend(['banker'])

        e.tag(tags)
