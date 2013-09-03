import urllib2
from datatypes.element import Hostname
from feed import Feed
import toolbox

class MDLHosts(Feed):
	"""
	This gets data from http://www.malwaredomainlist.com/hostslist/hosts.txt
	"""
	def __init__(self, name):
		super(MDLHosts, self).__init__(name, run_every="12h")
		self.enabled = False

	def update(self):
		try:
			feed = urllib2.urlopen("http://www.malwaredomainlist.com/hostslist/hosts.txt").readlines()
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
		hostname = Hostname(hostname=hostname, tags=['malwaredomainlist'])

		hostname, status = self.analytics.save_element(hostname, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


