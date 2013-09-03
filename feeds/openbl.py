import urllib2
from datatypes.element import Ip 
from feed import Feed
import toolbox

class OpenblIP(Feed):
	"""
	This gets data fromhttp://www.openbl.org/lists/base.txt 
	"""
	def __init__(self, name):
		super(OpenblIP, self).__init__(name, run_every="12h")
		self.enabled = False

	def update(self):
		try:
			feed = urllib2.urlopen("http://www.openbl.org/lists/base.txt").readlines()
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
		ip = Ip(ip=ip, tags=['openblip'])

		ip, status = self.analytics.save_element(ip, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


