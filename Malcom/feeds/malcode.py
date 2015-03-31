import bs4
from bson.json_util import dumps
from bson.objectid import ObjectId
import datetime
import md5
import re
import sys
import urllib2

import Malcom.auxiliary.toolbox as toolbox
from Malcom.feeds.feed import Feed
from Malcom.model.datatypes import Evil, Url


class MalcodeBinaries(Feed):

	def __init__(self, name):
		super(MalcodeBinaries, self).__init__(name, run_every="1h")
		self.name = "MalcodeBinaries"
		self.description = 	"Updated Feed of Malicious Executables"
		self.source	= "http://malc0de.com/rss/"

	def update(self):
		for dict in self.update_xml('item', ['title', 'description', 'link'], headers={"User-Agent": "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"}):
			self.analyze(dict)

		return True

	def analyze(self, dict):
		g = re.match(r'^URL: (?P<url>.+), IP Address: (?P<ip>[\d.]+), Country: (?P<country>[A-Z]{2}), ASN: (?P<asn>\d+), MD5: (?P<md5>[a-f0-9]+)$', dict['description'])
		if g:
			evil = g.groupdict()
			evil['description'] = "N/A"
			evil['link'] = dict['link']
			try:
				d=dict['description'].encode('UTF-8')
				evil['id'] = md5.new(d).hexdigest()
				evil['source'] = self.name
				url = Url(url=evil['url'])
				url.add_evil(evil)
				self.commit_to_db(url)
			except UnicodeError:
				sys.stderr.write('error Unicode : %s' % dict['description'])
			

