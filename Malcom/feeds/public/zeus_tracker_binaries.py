import datetime
import re
import md5

from Malcom.model.datatypes import Url
from Malcom.feeds.core import Feed


class ZeusTrackerBinaries(Feed):

    def __init__(self):
        super(ZeusTrackerBinaries, self).__init__()
        self.source = "https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries"
        self.description = "This feed shows the latest 50 ZeuS binary URLs."

    def update(self):
        for dict in self.update_xml('item', ["title", "link", "description", "guid"]):
            self.analyze(dict)

    def analyze(self, dict):
        evil = dict

        url = Url(re.search("URL: (?P<url>\S+),", dict['description']).group('url'))
        evil['id'] = md5.new(re.search(r"id=(?P<id>[a-f0-9]+)", dict['guid']).group('id')).hexdigest()

        try:
            date_string = re.search(r"\((?P<date>[0-9\-]+)\)", dict['title']).group('date')
            evil['date_added'] = datetime.datetime.strptime(date_string, "%Y-%m-%d")
        except AttributeError:
            pass

        try:
            evil['status'] = re.search(r"status: (?P<status>[^,]+)", dict['description']).group('status')
        except Exception:
            pass

        url.add_evil(evil)
        url.seen(first=evil['date_added'])
        self.commit_to_db(url)
