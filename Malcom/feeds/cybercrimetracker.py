import urllib2
import datetime, re
from lxml import etree
import Malcom.auxiliary.toolbox as toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from Malcom.model.datatypes import Evil, Url
from feed import Feed

class CybercrimeTracker(Feed):

	def __init__(self, name):
		super(CybercrimeTracker, self).__init__(name, run_every="12h")
		self.name = "CybercrimeTracker"
		self.description = "CyberCrime Tracker - Latest 20 CnC URLS"
		self.source = "http://cybercrime-tracker.net/rss.xml"
		self.confidence = 90
		
	def update(self, testing=False):
		self.update_xml('item', ["title", "link", "pubDate", "description"])

	def analyze(self, dict, testing=False):
		try:
			url = toolbox.find_urls(dict['title'])[0]
		except Exception, e:
			return # if no URL is found, bail

		# Create the new url and store it in the DB
		url = Url(url=url, tags=['cybercrimetracker', 'malware', dict['description'].lower()])

		evil = Evil()
		evil['value'] = "%s (%s CC)" % (url['value'], dict['description'].lower())
		evil['tags'] = ['cybercrimetracker', 'malware', 'cc', dict['description'].lower()]
		evil['info'] = "%s CC. Published on %s" % (dict['description'], dict['pubDate'])

		return url, evil