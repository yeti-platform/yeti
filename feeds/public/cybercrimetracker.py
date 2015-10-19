from datetime import datetime, timedelta

from core.datatypes import Element
from core.feed import Feed

class CybercrimeTracker(Feed):

    settings = {
        "frequency": timedelta(hours=1),
        "name": "CybercrimeTracker",
        "source": "http://cybercrime-tracker.net/rss.xml",
        "description": "CyberCrime Tracker - Latest 20 CnC URLS",
    }

    def update(self):
        for dict in self.update_xml('item', ["title", "link", "pubDate", "description"]):
            self.analyze(dict)

    def analyze(self, dict):
        element = dict['title']
        description = dict['description'].lower()
        context = {}
        context['description'] = "{} C2 server".format(description)
        context['date_added'] = datetime.strptime(dict['pubDate'], "%d-%m-%Y")
        context['source'] = self.name
        e = Element.add_text(element)
        e.add_context(context)

        tags = ['malware', 'c2', description, 'crimeware']
        if description == 'pony':
            tags.extend(['stealer', 'dropper'])
        elif description == 'athena':
            tags.extend(['stealer', 'ddos'])
        elif description in ['zeus', 'citadel']:
            tags.extend(['banker'])

        e.tag(tags)
