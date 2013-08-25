import urllib2
from datatypes.element import Hostname
from feed import Feed
import toolbox

class SuspiciousDomains(Feed):
	"""
	This gets data from https://isc.sans.edu/suspicious_domains.html
	Sensitivity level: high (for now)
	"""
	def __init__(self, name):
		super(SuspiciousDomains, self).__init__(name)
		self.enabled = False

	def update(self):
		try:
			feed = urllib2.urlopen("https://isc.sans.edu/feeds/suspiciousdomains_High.txt").readlines()
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
			# if find_hostname raises an exception, it means no hostname
			# was found in the line, so we return
			return

		# Create the new URL and store it in the DB
		hostname = Hostname(hostname=hostname, tags=['SuspiciousDomains', 'evil'])

		hostname, status = self.analytics.save_element(hostname, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


