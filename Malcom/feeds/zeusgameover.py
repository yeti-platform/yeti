import urllib2
from Malcom.model.datatypes import Hostname
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class ZeusGameOverDomains(Feed):
	"""
	This gets data from http://virustracker.info/text/ZeuSGameover_Domains.txt
	Sensitivity level: high (for now)
	"""
	def __init__(self, name):
		super(ZeusGameOverDomains, self).__init__(name, run_every="12h")
		self.enabled = True

	def update(self):
		try:
			feed = urllib2.urlopen("http://virustracker.info/text/ZeuSGameover_Domains.txt").readlines()
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
		hostname = Hostname(hostname=hostname, tags=['virustracker.info', 'zeusgameover'])

		hostname, status = self.analytics.save_element(hostname, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


