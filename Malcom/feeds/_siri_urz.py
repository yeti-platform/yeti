import urllib2
from Malcom.model.datatypes import Url 
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class SiriUrzVX(Feed):
	"""
	This gets data from http://vxvault.siri-urz.net/URL_List.php
	"""
	def __init__(self, name):
		super(SiriUrzVX, self).__init__(name, run_every="1h")
		self.name = "SiriUrzVX"
		

	def update(self):
		feed = urllib2.urlopen("http://vxvault.siri-urz.net/URL_List.php").readlines()
		self.status = "OK"
		
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

		url, new = self.model.save(url, with_status=True)
		if new:
			self.elements_fetched += 1


