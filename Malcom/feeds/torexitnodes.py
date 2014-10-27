import urllib2
from Malcom.model.datatypes import Ip, Evil
from feed import Feed
import Malcom.auxiliary.toolbox as toolbox
import time

class TorExitNodes(Feed):
	"""
	This gets data from https://www.dan.me.uk/tornodes
	"""
	def __init__(self, name):
		super(TorExitNodes, self).__init__(name, run_every="12h")
		self.name = "TorExitNodes"
		self.source = "https://www.dan.me.uk/tornodes"
		self.description = "List of Tor exit nodes"
		

	def update(self):
		feed = urllib2.urlopen(self.source).read()
		
		start = feed.find('<!-- __BEGIN_TOR_NODE_LIST__ //-->') + len('<!-- __BEGIN_TOR_NODE_LIST__ //-->')
		end = feed.find('<!-- __END_TOR_NODE_LIST__ //-->')

		feed=feed[start:end].replace('\n', '').replace('<br />','\n').replace('&gt;', '>').replace('&lt;', '<').split('\n')
		
		if len(feed) > 10:
			self.status = "OK"
		
		for line in feed:	
			self.analyze(line)
		return True

	def analyze(self, line):
		fields = line.split('|')

		tornode = Evil(tags=['tor exit node'])
		#
		try:
			tornode['ip'] = fields[0]
			tornode['name'] = fields[1]
			tornode['router-port'] = fields[2]
			tornode['directory-port'] = fields[3]
			tornode['flags'] = fields[4]
			tornode['uptime'] = fields[5]
			tornode['version'] = fields[6]
			tornode['contactinfo'] = fields[7]
		except Exception, e:
			return


		tornode['value'] = "Tor node: %s (%s)" % (tornode['name'], tornode['ip'])

		try:
			ip = toolbox.find_ips(tornode['ip'])[0]
			ip = Ip(ip=ip, tags=['tor'])
		except Exception, e:
			# if find_ip raises an exception, it means no ip 
			# was found in the line, so we return
			return

		self.commit_to_db(ip, tornode, "Tor node")

