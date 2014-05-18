import urllib2
from Malcom.model.datatypes import Hostname
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
		feed = urllib2.urlopen(self.source).readlines()
		self.status = "OK"
		
		for line in feed:	
			self.analyze(line)
		return True

	def analyze(self, line):
		if line.startswith('#') or line.startswith('\n'):
			return

		try:
			hostname = toolbox.find_hostnames(line)[0]
		except Exception, e:
			return

		# Create the new ip and store it in the DB
		hostname = Hostname(hostname=hostname, tags=['dshield', 'high'])

		hostname, new = self.model.save(hostname, with_status=True)
		if new:
			self.elements_fetched += 1


