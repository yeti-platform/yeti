import urllib2
import datetime, re
from lxml import etree
import Malcom.auxiliary.toolbox as toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from Malcom.model.datatypes import Evil, Url
from feed import Feed



class SpyEyeDropzones(Feed):

	def __init__(self, name):
		super(SpyEyeDropzones, self).__init__(name, run_every="1h")
		self.enabled = True


	def update(self):
		try:
			feed = urllib2.urlopen("https://spyeyetracker.abuse.ch/monitor.php?rssfeed=dropurls")
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

		evil['feed'] = "SpyEyeDropzones"
		evil['url'] = toolbox.find_urls(dict['description'])[0]
		
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
		evil['tags'] += ['spyeye', 'malware', 'SpyEyeDropzones']

		# date_retreived
		evil['date_retreived'] = datetime.datetime.utcnow()

		# This is important. Values have to be unique, since it's this way that
		# Malcom will identify them in the database.
		# This is probably not the best way, but it will do for now.

		evil['value'] = "SpyEye Dropzone (%s)"%evil['url']

		# Save elements to DB. The status field will contain information on 
		# whether this element already existed in the DB.

		evil, status = self.analytics.save_element(evil, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1

		# Create an URL element
		url = Url(evil['url'], ['evil', 'SpyEyeDropzones'])

		# Save it to the DB.
		url, status = self.analytics.save_element(url, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1

		# Connect the URL element to the Evil element
		self.analytics.data.connect(url, evil, 'hosting')

