import urllib2
import datetime, re
from lxml import etree
import Malcom.auxiliary.toolbox as toolbox

from bson.objectid import ObjectId
from bson.json_util import dumps
from Malcom.model.datatypes import Hostname, Evil, Ip
from feed import Feed



class SpyEyeTracker(Feed):

	def __init__(self, name):
		super(SpyEyeTracker, self).__init__(name, run_every="1h")
		self.name = "SpyEyeTracker"
		self.source = "https://spyeyetracker.abuse.ch/monitor.php?rssfeed=tracker"
		self.description = "This feed shows the latest forty SpyEye C&Cs which the tracker has captured."

	def update(self):
		self.update_xml('item', ["title", "link", "description", "guid"])


	def analyze(self, dict):
			
		# We create an Evil object. Evil objects are what Malcom uses
		# to store anything it considers evil. Malware, spam sources, etc.
		# Remember that you can create your own datatypes, if need be.

		evil = Evil()

		# We start populating the Evil() object's attributes with
		# information from the dict we parsed earlier
		
		# description
		evil['description'] = dict['link'] + " " + dict['description'] 

		# status
		status = re.search("Status: (?P<status>\S+),", dict['description'])
		if status:
			evil['status'] = status.group('status')
		else:
			evil['status'] = "unknown"
			
		# linkback
		evil['guid'] = dict['guid']

		# tags
		evil['tags'] += ['spyeye', 'malware', 'cc']

		# This is important. Values have to be unique, since it's this way that
		# Malcom will identify them in the database.
		# This is probably not the best way, but it will do for now.
		
		host = re.search("Host: (?P<host>\S+),", dict['description']).group("host")
		
		if toolbox.find_ips(host):
			elt = Ip(host, tags=['cc', 'spyeye', 'malware'])
		else:
			elt = Hostname(host, tags=['cc', 'spyeye', 'malware'])

		evil['value'] = "SpyEye CC (%s)" % elt['value']
		
		# Save elements to DB. The status field will contain information on 
		# whether this element already existed in the DB.

		return elt, evil

		self.commit_to_db(elt, evil)

