import urllib2
import datetime, re
from lxml import etree
import Malcom.auxiliary.toolbox as toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from Malcom.model.datatypes import Evil, Url
from feed import Feed


class MalcodeBinaries(Feed):

	def __init__(self, name):
		super(MalcodeBinaries, self).__init__(name, run_every="1h")
		self.name = "MalcodeBinaries"
		self.description = 	"Updated Feed of Malicious Executables"
		self.source	= "http://malc0de.com/rss/"

	def update(self):
		
		request = urllib2.Request(self.source, headers={"User-agent": "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"})
		feed = urllib2.urlopen(request)
		
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

		try:
			url = toolbox.find_urls(dict['description'])[0]
		except Exception, e:
			return # no URL found, bail

		url = Url(url=url, tags=['exe'])
			
		# We create an Evil object. Evil objects are what Malcom uses
		# to store anything it considers evil. Malware, spam sources, etc.
		# Remember that you can create your own datatypes, if need be.

		evil = Evil()

		# We start populating the Evil() object's attributes with
		# information from the dict we parsed earlier
		
		evil['info'] = dict['description']  # description
		evil['tags'] = [self.name, 'malware']
	
		md5 = re.search("MD5 hash: (?P<md5>[0-9a-f]{32,32})", dict['description']) # md5 
		if md5 != None:
			evil['md5'] = md5.group('md5')
		else:
			evil['md5'] = "No MD5"
		
		evil['link'] = dict['link'] # linkback

		# This is important. Values have to be unique, since it's this way that
		# Malcom will identify them in the database.
		# This is probably not the best way, but it will do for now.

		evil['value'] = "Malcode malware URL"
		if md5:
			evil['value'] += " (MD5: %s)" % evil['md5']
		else:
			evil['value'] += " (URL: %s)" % url['value']

		# Save elements to DB. The status field will contain information on 
		# whether this element already existed in the DB.

		self.commit_to_db(url, evil)
