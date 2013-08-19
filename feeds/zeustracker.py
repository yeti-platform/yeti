import urllib2
import datetime, re
from lxml import etree
import toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from datatypes.element import Evil, Url
from feed import Feed



class ZeusTrackerBinaries(Feed):

	display = [  ("url", "URL"),
				 ("description", "Description"),
				 ("status", "Status"),
				 ("md5", "MD5"),
				 ("source", "Source"),
				 ("type", "Type"),
				 ("date_retreived", "Retrived")
				]

	def __init__(self, name):
		super(ZeusTrackerBinaries, self).__init__(name)


	def update(self):
		try:
			feed = urllib2.urlopen("https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries")
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
			
		# Evil object
		evil = Evil()

		evil['feed'] = "ZeusTrackerBinaries"
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

		# context
		evil['context'] += ['zeus', 'malware', 'ZeusTrackerBinaries']

		# date_retreived
		evil['date_retreived'] = datetime.datetime.utcnow()

		evil['value'] = "ZeuS bot"
		if md5:
			evil['value'] += " (MD5: %s)" % evil['md5']
		else:
			evil['value'] += " (URL: %s)" % evil['url']

		# commit to db
		evil, status = self.analytics.save_element(evil, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1

		# URL object
		url = Url(evil['url'], ['evil', 'ZeusTrackerBinaries'])

		# commit to db
		url, status = self.analytics.save_element(url, with_status=True)
		if status['updatedExisting'] == False:
			self.elements_fetched += 1

		# connect url with malware
		self.analytics.data.connect(url, evil, ['hosting'])

