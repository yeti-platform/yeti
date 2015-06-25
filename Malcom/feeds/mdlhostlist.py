import urllib2
import re
import md5
from lxml import etree

import Malcom.auxiliary.toolbox as toolbox
from Malcom.model.datatypes import Url
from Malcom.feeds.feed import Feed

class MalwareDomainList(Feed):
	"""
	This gets data from http://www.malwaredomainlist.com/hostslist/mdl.xml
	"""
	def __init__(self, name):
		super(MalwareDomainList, self).__init__(name, run_every="12h")
		self.source = "http://www.malwaredomainlist.com/hostslist/mdl.xml"
		self.description = "MalwareDomainList update. This feed shows the latest urls which have been added to our list."
		self.name = "MalwareDomainList"

	def update(self):
		for dict in self.update_xml('item', ["title", "link", "description", "guid"]):
			self.analyze(dict)

	def analyze(self, dict):

		# Create the new URL and store it in the DB
		evil = dict
		url = Url(url=re.search("Host: (?P<url>[^,]+),", dict['description']).group('url'))
		evil['id'] = md5.new(dict['guid']).hexdigest()
		url.add_evil(evil)
		url.seen()
		self.commit_to_db(url)


