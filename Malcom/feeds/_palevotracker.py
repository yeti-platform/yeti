import urllib2
from Malcom.model.datatypes import Hostname
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
		feed = urllib2.urlopen(self.source)
		self.status = "OK"
		
		children = ["title", "link", "description", 'guid']
		main_node = "item"
		
		tree = etree.parse(feed)
		for item in tree.findall("//%s"%main_node):
			dict = {}
			for field in children:
				dict[field] = item.findtext(field)

			self.analyze(dict)

		return True

	def analyze(self, line):
		if line.startswith('#') or line.startswith('\n'):
			return
		try:
			hostname = toolbox.find_hostnames(line)[0]
		except Exception, e:
			# if find_hostname raises an exception, it means no hostname
			# was found in the line, so we return
			return

		# Create the new Hostname and store it in the DB
		hostname = Hostname(hostname=hostname)
		
		evil = Evil()
		evil['value'] = "Palevo CC (%s)" % hostname['value']
		evil['status'] = re.search("Status: (?<status>[^<]+<)", dict['description']).group('status')
		evil['info'] = dict['description']
		evil['tags'] = ['cc', 'palevo']

		self.commit_to_db(hostname, evil)


