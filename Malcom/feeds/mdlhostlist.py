import urllib2, re
import Malcom.auxiliary.toolbox as toolbox
from Malcom.model.datatypes import Url, Evil
from feed import Feed
from lxml import etree

class MDLHosts(Feed):
	"""
	This gets data from http://www.malwaredomainlist.com/hostslist/mdl.xml
	"""
	def __init__(self, name):
		super(MDLHosts, self).__init__(name, run_every="12h")
		self.source = "http://www.malwaredomainlist.com/hostslist/mdl.xml"
		self.description = "MalwareDomainList update. This feed shows the latest urls which have been added to our list."
		self.name = "MalwareDomainList"

	def update(self):
		self.update_xml('item', ["title", "link", "description", "guid"])

	def analyze(self, dict):

		# Create the new URL and store it in the DB
		url = re.search("Host: (?P<url>[^,]+),", dict['description']).group('url')
		url = Url(url=url)
		evil = Evil()
		
		evil['details'] = dict['description']
		threat_type = re.search('Description: (?P<tag>.+)', dict['description']).group('tag')
		evil['tags'] = ['malwaredomainlist', threat_type]
		evil['value'] = "%s (%s)" % (threat_type, url['value'])
		evil['link'] = dict['link']
		evil['guid'] = dict['guid']

		return url, evil


