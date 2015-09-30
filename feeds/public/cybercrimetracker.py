from datetime import datetime, timedelta

from core.db.datatypes import Url
from core.feed import Feed

class CybercrimeTracker(Feed):

    # tags = description

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
        url = dict['title']
        context = {}
        context['description'] = "%s CC" % (dict['description'].lower())
        context['date_added'] = datetime.strptime(dict['pubDate'], "%d-%m-%Y")
        context['source'] = self.name
        url = Url.get_or_create(url)
        url.add_context(context)
