import urllib2
from datatypes.element import Url 
from feed import Feed
import toolbox

class SiriUrzVX(Feed):
	"""
	This gets data from http://vxvault.siri-urz.net/URL_List.php
	"""
	def __init__(self, name):
		super(SiriUrzVX, self).__init__(name, run_every="1h")
		self.enabled = True

	def update(self):
		try:
			feed = urllib2.urlopen("http://vxvault.siri-urz.net/URL_List.php").readlines()
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
			url = toolbox.find_urls(line)[0]

		except Exception, e:
			# if find_ip raises an exception, it means no ip 
			# was found in the line, so we return
			return

		# Create the new ip and store it in the DB
		url =Url(url=url, tags=['siri-urz'])

		url, status = self.analytics.save_element(url, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1


