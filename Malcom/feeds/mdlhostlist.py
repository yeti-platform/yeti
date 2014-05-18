import urllib2
import Malcom.auxiliary.toolbox as toolbox
from Malcom.model.datatypes import Hostname, Evil
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
		feed = urllib2.urlopen(self.source)
		self.status = "OK"
		
		children = ["title", "link", "description", "guid"]
		main_node = "item"
		
		tree = etree.parse(feed)
		for item in tree.findall("//%s"%main_node):
			dict = {}
			for field in children:
				dict[field] = item.findtext(field)

			self.analyze(dict)

		return True

	def analyze(self, dict):
		if line.startswith('#') or line.startswith('\n'):
			return
		try:
			hostname = toolbox.find_hostnames(line)[0]
		except Exception, e:
			# if find_hostname raises an exception, it means no hostname
			# was found in the line, so we return
			return

		# Create the new URL and store it in the DB
		url = re.search("Host: (?<url>[^,]),", dict['description']).group('url')
		url = Url(value=url)
		evil = Evil()
		
		evil['details'] = dict['description']
		threat_type = re.search('Description :(?<tag>[^,]+,)').group('tag')
		evil['tags'] = ['malwaredomainlist', threat_type]
		evil['value'] = "%s (%s)" % (threat_type, url['value'])
		evil['link'] = dict['link']
		evil['guid'] = dict['guid']

		self.commit_to_db(url, evil)


