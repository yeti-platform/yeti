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
		self.enabled = True

	def update(self):
		try:
			feed = urllib2.urlopen("http://cybercrime-tracker.net/rss.xml")	#Xylitol's tracker
			self.status = "OK"
		except Exception, e:
			self.status = "ERROR: " + str(e)
			return False

		children = ["title", "link", "pubDate", "description"]
		main_node = "item"
		
		tree = etree.parse(feed)
		for item in tree.findall("//%s"%main_node):
			dict = {}
			for field in children:
				dict[field] = item.findtext(field)

			self.analyze(dict)

		return True

	def analyze(self, dict):
		try:
			url = toolbox.find_urls(dict['title'])[0]
		except Exception, e:
			return

		# Create the new url and store it in the DB
		url =Url(url=url, tags=['cybercrimetracker', 'malware', dict['description']])

		url, status = self.analytics.save_element(url, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1