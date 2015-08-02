import urllib2
import datetime
import re
import md5

from bson.objectid import ObjectId
from bson.json_util import dumps

import Malcom.auxiliary.toolbox as toolbox
from Malcom.model.datatypes import Ip, Hostname
from Malcom.feeds.core import Feed

class FeodoTracker(Feed):

	descriptions = {
				'A': "Hosted on compromised webservers running an nginx proxy on port 8080 TCP forwarding all botnet traffic to a tier 2 proxy node. Botnet traffic usually directly hits these hosts on port 8080 TCP without using a domain name.",
				'B': "Hosted on servers rented and operated by cybercriminals for the exclusive purpose of hosting a Feodo botnet controller. Usually taking advantage of a domain name within ccTLD .ru. Botnet traffic usually hits these domain names using port 80 TCP.",
				'C': "Successor of Feodo, completely different code. Hosted on the same botnet infrastructure as Version A (compromised webservers, nginx on port 8080 TCP or port 7779 TCP, no domain names) but using a different URL structure. This Version is also known as Geodo.",
				'D': "Successor of Cridex. This version is also known as Dridex",
				}

	variants = {
				'A': "Feodo",
				'B': "Feodo",
				'C': "Geodo",
				'D': "Dridex",
				}

	def __init__(self):
		super(FeodoTracker, self).__init__()
		self.source = "https://feodotracker.abuse.ch/feodotracker.rss"
		self.description = "Feodo Tracker RSS Feed. This feed shows the latest twenty Feodo C2 servers which Feodo Tracker has identified."


	def update(self):
		for dict in self.update_xml('item', ["title", "link", "description", "guid"]):
			self.analyze(dict)

	def analyze(self, dict):
		evil = dict


		date_string = re.search(r"\((?P<datetime>[\d\- :]+)\)", dict['title']).group('datetime')
		try:
			evil['date_added'] = datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
		except ValueError, e:
			pass

		g = re.match(r'^Host: (?P<host>.+), Version: (?P<version>\w)', dict['description'])
		g = g.groupdict()
		evil['host'] = g['host']
		evil['version'] = g['version']
		evil['description'] = FeodoTracker.descriptions[g['version']]
		evil['id'] = md5.new(dict['description']).hexdigest()
		evil['source'] = self.name
		del evil['title']


		if toolbox.is_ip(evil['host']):
			elt = Ip(ip=evil['host'], tags=[FeodoTracker.variants[g['version']]])
		elif toolbox.is_hostname(evil['host']):
			elt = Hostname(hostname=evil['host'], tags=[FeodoTracker.variants[g['version']]])

		elt.seen(first=evil['date_added'])
		elt.add_evil(evil)
		self.commit_to_db(elt)


