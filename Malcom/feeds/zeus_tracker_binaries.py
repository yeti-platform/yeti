import urllib2
import datetime
import re
import md5

from lxml import etree
from bson.objectid import ObjectId
from bson.json_util import dumps

from Malcom.model.datatypes import Url
from Malcom.feeds.feed import Feed
import Malcom.auxiliary.toolbox as toolbox

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
        except AttributeError, e:
            print "Date not found!"

        try:
            evil['status'] = re.search(r"status: (?P<status>[^,]+)", dict['description']).group('status')
        except Exception, e:
            print "status not found!"

        url.add_evil(evil)
        url.seen(first=evil['date_added'])
        self.commit_to_db(url)