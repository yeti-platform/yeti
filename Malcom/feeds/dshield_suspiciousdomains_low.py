import urllib2
from Malcom.model.datatypes import Hostname
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class DShieldSuspiciousDomainsLow(Feed):
	def __init__(self, name):
		super(DShieldSuspiciousDomainsLow, self).__init__(name)
		self.enabled = True

	def update(self):
		try:
			feed = urllib2.urlopen("http://www.dshield.org/feeds/suspiciousdomains_Low.txt").readlines()
			self.status = "OK"
		except Exception, e:
			self.status = "ERROR: " + str(e)
			return False
		
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

		hostname, status = self.analytics.save_element(hostname, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


