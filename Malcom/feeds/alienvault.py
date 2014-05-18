import urllib2, re
from Malcom.model.datatypes import Ip, Evil
from Malcom.feeds.feed import Feed
import Malcom.auxiliary.toolbox as toolbox



class AlienvaultIP(Feed):
	"""
	This gets data from https://reputation.alienvault.com/reputation.generic
	"""

	def __init__(self, name):
		super(AlienvaultIP, self).__init__(name, run_every="12h")
		self.name = "Alienvault"
		self.description = "Alienvault IP Reputation Database"
		self.source = "https://reputation.alienvault.com/reputation.generic"
		self.confidence = 50

	def update(self):
		
		feed = urllib2.urlopen("https://reputation.alienvault.com/reputation.generic").readlines()
		self.status = "OK"
		
		for line in feed:	
			self.analyze(line)

		return True

	def analyze(self, line):

		if line.startswith('#') or line.startswith('\n'):
			return
		try:
			ip = toolbox.find_ips(line)[0]
			description = re.search(" # (?P<description>[^,]+),", line)
			if description:
				description = description.group('description')
			else:
				description = False
		except Exception, e:
			# if find_ip raises an exception, it means no ip 
			# was found in the line, we bail
			return

		if not description:
			return # we're not interested in non-qualified information

		# Create the new ip and store it in the DB
		ip = Ip(ip=ip, tags=['alienvault'])

		# Create the new Evil and store it in the DB
		evil = Evil()
		evil['value'] = ip['value'] + ' (%s)' % description
		evil['tags'] = ['AlienvaultIP', description]

		self.commit_to_db(ip, evil)



