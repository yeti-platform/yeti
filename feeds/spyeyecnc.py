import urllib2
import datetime, re
from lxml import etree
import toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from datatypes.element import Hostname
from feed import Feed



class SpyEyeCnc(Feed):

	def __init__(self, name):
		super(SpyEyeCnc, self).__init__(name, run_every="1h")
		self.enabled = False


	def update(self):
		try:
			feed = urllib2.urlopen("https://spyeyetracker.abuse.ch/monitor.php?rssfeed=tracker")
			self.status = "OK"
		except Exception, e:
			self.status = "ERROR: " + str(e)
			return False
		
		children = ["title", "link", "description", "guid"]
		main_node = "item"
		

		tree = etree.parse(feed)
		for item in tree.findall("//%s"%main_node):
			dict = {}
			for field in children:
				dict[field] = item.findtext(field)

			self.analyze(dict)

		return True

	def analyze(self, dict):
			
		# We create an Evil object. Evil objects are what Malcom uses
		# to store anything it considers evil. Malware, spam sources, etc.
		# Remember that you can create your own datatypes, if need be.

		evil = Evil()

		# We start populating the Evil() object's attributes with
		# information from the dict we parsed earlier

		evil['feed'] = "SpyEyeConfigs"
		evil['hostname'] = toolbox.find_hostnames(dict['description'])[0]
		
		# description
		evil['description'] = dict['link'] + " " + dict['description'] 

		# status
		if dict['description'].find("offline") != -1:
			evil['status'] = "offline"
		else:
			evil['status'] = "online"

		# md5 
		md5 = re.search("MD5 hash: (?P<md5>[0-9a-f]{32,32})",dict['description'])
		if md5 != None:
			evil['md5'] = md5.group('md5')
		else:
			evil['md5'] = "No MD5"
		
		# linkback
		evil['source'] = dict['guid']

		# type
		evil['type'] = 'evil'

		# tags
		evil['tags'] += ['spyeye', 'malware', 'SpyEyeCnc']

		# date_retreived
		evil['date_retreived'] = datetime.datetime.utcnow()

		# This is important. Values have to be unique, since it's this way that
		# Malcom will identify them in the database.
		# This is probably not the best way, but it will do for now.

		evil['value'] = "SpyEye Config"
		if md5:
			evil['value'] += " (MD5: %s)" % evil['md5']
		else:
			evil['value'] += " (URL: %s)" % evil['url']

		# Save elements to DB. The status field will contain information on 
		# whether this element already existed in the DB.

		evil, status = self.analytics.save_element(evil, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1

		# Create an URL element
		hostname = Hostname(evil['hostname'], ['evil', 'SpyEyeConfigs'])

		# Save it to the DB.
		url, status = self.analytics.save_element(hostname, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1

		# Connect the URL element to the Evil element
		self.analytics.data.connect(hostname, evil, 'hosting')

