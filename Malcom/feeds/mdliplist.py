import urllib2
from Malcom.model.datatypes import Ip 
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class MDLIpList(Feed):
	"""
	This gets data from http://www.malwaredomainlist.com/hostslist/ip.txt 
	"""
	def __init__(self, name):
		super(MDLIpList, self).__init__(name)
		self.enabled = True

	def update(self):
		try:
			feed = urllib2.urlopen("http://www.malwaredomainlist.com/hostslist/ip.txt").readlines()
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
			ip = toolbox.find_ips(line)[0]
		except Exception, e:
			# if find_ip raises an exception, it means no ip 
			# was found in the line, so we return
			return

		# Create the new ip and store it in the DB
		ip = Ip(ip=ip, tags=['mdliplist'])

		ip, status = self.analytics.save_element(ip, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


