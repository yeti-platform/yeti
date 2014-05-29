import urllib2
from Malcom.model.datatypes import Hostname, Evil
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class DShieldSuspiciousDomainsMedium(Feed):
	def __init__(self, name):
		super(DShieldSuspiciousDomainsMedium, self).__init__(name)
		self.name = "DShieldSuspiciousDomainsMedium"
		self.description = "DShield medium sensitivity suspicious domains"
		self.source = "http://www.dshield.org/feeds/suspiciousdomains_Medium.txt"
		self.confidence = 10
		
	def update(self):
		self.update_lines()

	def analyze(self, line):
		if line.startswith('#') or line.startswith('\n'):
			return

		try:
			hostname = toolbox.find_hostnames(line)[0]
		except Exception, e:
			return

		# Create the new ip and store it in the DB
		hostname = Hostname(hostname=hostname, tags=['evil'])
		
		evil = Evil()
		evil['value'] = "%s (DShield suspicious domain)" % hostname['value']
		evil['tags'] = ['dshield', 'medium']

		return hostname, evil

