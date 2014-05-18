import urllib2
from Malcom.model.datatypes import Hostname
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class DShieldSuspiciousDomainsLow(Feed):
	def __init__(self, name):
		super(DShieldSuspiciousDomainsLow, self).__init__(name)
		self.name = "DShieldSuspiciousDomainsLow"
		self.description = "DShield low sensitivity suspicious domains"
		self.source = "http://www.dshield.org/feeds/suspiciousdomains_Low.txt"
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
		hostname = Hostname(hostname=hostname, tags=['dshield', 'low'])

		hostname, new = self.model.save(hostname, with_status=True)
		if new:
			self.elements_fetched += 1


