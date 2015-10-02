import re
from datetime import timedelta
from datetime import datetime

from core.feed import Feed
from core.db.datatypes import Url

class ZeusTrackerBinaries(Feed):

    settings = {  "frequency": timedelta(hours=1),
                  "name": "ZeusTrackerBinaries",
                  "source": "https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries",
                  "description": "This feed shows the latest 50 ZeuS binaries URLs.",
                }

    def update(self):
        for d in self.update_xml('item', ["title", "link", "description", "guid"]):
            self.analyze(d)

    def analyze(self, dict):
        url_string = re.search(r"URL: (?P<url>\S+),", dict['description']).group('url')
        url_string = url_string.replace('http://https:', 'https://')
        context = {}
        date_string = re.search(r"\((?P<date>[0-9\-]+)\)", dict['title']).group('date')
        context['date_added'] = datetime.strptime(date_string, "%Y-%m-%d")
        context['status'] = re.search(r"status: (?P<status>[^,]+)", dict['description']).group('status')
        context['guid'] = dict['guid']
        context['source'] = self.name
        try:
            context['md5'] = re.search(r"MD5 hash: (?P<md5>[a-f0-9]+)", dict['description']).group('md5')
        except AttributeError as e:
            pass

        n = Url.get_or_create(url_string)
        n.add_context(context)
        n.tag(['zeus', 'delivery', 'banker', 'cirmeware', 'malware'])
