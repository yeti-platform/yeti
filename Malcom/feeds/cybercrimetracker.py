import urllib2
import datetime
import re
import md5

from bson.objectid import ObjectId
from bson.json_util import dumps

from Malcom.model.datatypes import Url
from Malcom.feeds.feed import Feed
import Malcom.auxiliary.toolbox as toolbox


class CybercrimeTracker(Feed):

	def __init__(self, name):
		super(CybercrimeTracker, self).__init__(name, run_every="12h")
		self.name = "CybercrimeTracker"
		self.description = "CyberCrime Tracker - Latest 20 CnC URLS"
		self.source = "http://cybercrime-tracker.net/rss.xml"
		self.confidence = 90

	def update(self):
		for dict in self.update_xml('item', ["title", "link", "pubDate", "description"]):
			self.analyze(dict)


	def analyze(self, dict):
		try:
			url = toolbox.find_urls(dict['title'])[0]
		except Exception, e:
			return # if no URL is found, bail

		url = Url(url=url, tags=[dict['description'].lower()])

		evil = {}
		evil['description'] = "%s CC" % (dict['description'].lower())
		evil['date_added'] = datetime.datetime.strptime(dict['pubDate'], "%d-%m-%Y")
		evil['id'] = md5.new(dict['title']+dict['pubDate']+dict['description']).hexdigest()
		evil['source'] = self.name

		url.seen(first=evil['date_added'])
		url.add_evil(evil)
		self.commit_to_db(url)
