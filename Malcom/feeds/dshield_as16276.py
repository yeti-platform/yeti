import urllib2
from Malcom.model.datatypes import Ip 
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox

class DShield16276(Feed):
	"""
	This gets data from http://dshield.org/asdetailsascii.html?as=16276
	"""
	def __init__(self, name):
		super(DShield16276, self).__init__(name)
		self.name = "DShield16276"
		self.source = "http://dshield.org/asdetailsascii.html?as=16276"
		self.description = "DShield scanning report for AS 16276"
		self.confidence = 30
		

	def update(self):
		feed = urllib2.urlopen(self.source).readlines()
		self.status = "OK"
		
		for line in feed:	
			self.analyze(line)
		return True

	def analyze(self, line):
		if line.startswith('#') or line.startswith('\n'):
			return
		dict = line.split('\t')
		if int(dict[2]) < 300: # skip entries which have not been reported at least 300 times
			return

		try:
			ip = toolbox.find_ips(line)[0]
		except Exception, e:
			# if find_ip raises an exception, it means no ip 
			# was found in the line, so we return
			return

		# Create the new ip and store it in the DB
		dict = line.split('\t')
		ip = Ip(ip=ip, tags=['dshield'])
		evil = Evil()
		evil['value'] = 'Scanner at %s' % ip['value']
		evil['reports'] = dict[2]
		evil['first seen'] = dict[3]
		evil['last seen'] = dict[4]

		self.commit_to_db(ip, evil)

