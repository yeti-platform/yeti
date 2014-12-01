import urllib2
import datetime, re
from lxml import etree
import Malcom.auxiliary.toolbox as toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from Malcom.model.datatypes import Evil, Ip, Hostname
from feed import Feed

class FeodoTracker(Feed):

	def __init__(self, name):
		super(FeodoTracker, self).__init__(name)
		self.name = "FeodoTracker"
		self.source = "https://feodotracker.abuse.ch/feodotracker.rss"
		self.description = "This feed shows Feodo/Dridex C2 infrastructure"
		

	def update(self):
		self.update_xml('item', ["title", "link", "description", "guid"])

	def analyze(self, dict):

		evil = Evil()

		# description
		evil['description'] = dict['description'] 

		host = re.search("Host: (?P<host>\S+),", dict['description'])
		if host:
			if toolbox.is_ip(host.group('host')):
				host = Ip(toolbox.is_ip(host.group('host')))
			elif toolbox.is_hostname(host.group('host')):
				host = Hostname(toolbox.is_hostname(host.group('host')))
			else:
				return None, None

		version = re.search("Version: (?P<version>[ABCD])", dict['description'])
		if version != None:
			evil['version'] = version
		else:
			evil['version'] = 'N/A'

		# linkback
		evil['link'] = dict['link']

		# tags
		evil['tags'] += ['feodo', 'cridex', 'malware', 'exe']

		evil['value'] = "Feodo C2 ({})".format(host['value'])

		return host, evil