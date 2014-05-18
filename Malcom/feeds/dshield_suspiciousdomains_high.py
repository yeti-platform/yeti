import urllib2
from Malcom.model.datatypes import Hostname, Evil
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class DShieldSuspiciousDomainsHigh(Feed):
	def __init__(self, name):
		super(DShieldSuspiciousDomainsHigh, self).__init__(name)
		self.name = "DShieldSuspiciousDomainsHigh"
		self.description = "DShield high sensitivity suspicious domains"
		self.source = "http://www.dshield.org/feeds/suspiciousdomains_High.txt"
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

		# Create the new hostname
		hostname = Hostname(hostname=hostname, tags=['evil'])

		evil = Evil()
		evil['value'] = "%s (suspicious domain)" % hostname['value']
		evil['tags'] = ['dshield', 'high']

		return hostname, evil

