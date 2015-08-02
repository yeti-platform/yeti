import urllib2
import re
import md5

from lxml import etree

from Malcom.feeds.core import Feed
from Malcom.model.datatypes import Hostname
import Malcom.auxiliary.toolbox as toolbox


class PalevoTracker(Feed):
	"""
	This gets data from https://palevotracker.abuse.ch/?rssfeed
	"""
	def __init__(self):
		super(PalevoTracker, self).__init__(run_every="1h")
		self.description = "List of the twenty most recent Palevo Botnet C&amp;C servers Palevo Tracker came across of."
		self.source = "https://palevotracker.abuse.ch/?rssfeed"

	def update(self):
		for dict in self.update_xml('item', ["title", "link", "description", 'guid']):
			self.analyze(dict)

	def analyze(self, dict):

		# Create the new Hostname and store it in the DB

		hostname = Hostname(hostname=toolbox.find_hostnames(dict['title'])[0])
		if hostname['value'] == None: return

		evil = dict
		evil['status'] = re.search("Status: (?P<status>\S+)", dict['description']).group('status')
		evil['id'] = md5.new(re.search(r"id=(?P<id>[a-f0-9]+)", dict['guid']).group('id')).hexdigest()
		evil['source'] = self.name

		hostname.seen()
		hostname.add_evil(evil)
		self.commit_to_db(hostname)


