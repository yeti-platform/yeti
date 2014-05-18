import urllib2, re
from Malcom.model.datatypes import Hostname, Evil
from feed import Feed
from lxml import etree
import Malcom.auxiliary.toolbox as toolbox

class PalevoTracker(Feed):
	"""
	This gets data from https://palevotracker.abuse.ch/?rssfeed
	"""
	def __init__(self, name):
		super(PalevoTracker, self).__init__(name, run_every="1h")
		self.name = "PalevoTracker"
		self.description = "List of the twenty most recent Palevo Botnet C&amp;C servers Palevo Tracker came across of."
		self.source = "https://palevotracker.abuse.ch/?rssfeed"

	def update(self):
		self.update_xml('item', ["title", "link", "description", 'guid'])

	def analyze(self, dict):

		# Create the new Hostname and store it in the DB
		hostname = Hostname(hostname=toolbox.find_hostnames(dict['title'])[0])
		if hostname['value'] == None: return
		
		evil = Evil()
		evil['value'] = "Palevo CC (%s)" % hostname['value']
		evil['status'] = re.search("Status: (?P<status>\S+)", dict['description']).group('status')
		evil['info'] = dict['description']
		evil['tags'] = ['cc', 'palevo']

		return hostname, evil


