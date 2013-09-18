import urllib2
import datetime, re
from lxml import etree
import toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from datatypes.element import Evil, Url
from feed import Feed



class MDLTracker(Feed):

	def __init__(self, name):
		super(MDLTracker, self).__init__(name, run_every="1h")
		self.enabled = True


	def update(self):
		try:
			feed = urllib2.urlopen("http://www.malwaredomainlist.com/hostslist/mdl.xml")
			self.status = "OK"
		except Exception, e:
			self.status = "ERROR: " + str(e)
			return False
		
		children = ["title", "description", "link"]
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

		#print dict
		#return
		mdl = Url()

		# We start populating the Evil() object's attributes with
		# information from the dict we parsed earlier

		mdl['feed'] = "MDLTracker"
		try: 
			mdl['value'] = toolbox.find_urls(dict['description'])[0]
		except Exception,e:
			return
			
		# description
		mdl['description'] = dict['title'] 

		# linkback
		mdl['source'] = dict['link']

		#tags 
		mdl['tags'] = ['ek', 'malware', 'MDLTracker', 'evil']

		# date_retreived
		mdl['date_retreived'] = datetime.datetime.utcnow()

		# Save elements to DB. The status field will contain information on 
		# whether this element already existed in the DB.

		mdl, status = self.analytics.save_element(mdl, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1

