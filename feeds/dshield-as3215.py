import urllib2
from datatypes.element import Ip 
from feed import Feed
import toolbox

class DShield3215(Feed):
	"""
	This gets data from http://dshield.org/asdetailsascii.html?as=3215
	"""
	def __init__(self, name):
		super(DShield3215, self).__init__(name)
		self.enabled = True

	def update(self):
		try:
			feed = urllib2.urlopen("http://dshield.org/asdetailsascii.html?as=3215").readlines()
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
		ip = Ip(ip=ip, tags=['dshield'])

		ip, status = self.analytics.save_element(ip, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


