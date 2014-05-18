import urllib2
import re
from lxml import etree
import Malcom.auxiliary.toolbox as toolbox
from Malcom.model.datatypes import Url
from feed import Feed

class UrlQuery(Feed):

	def __init__(self, name):
		super(UrlQuery, self).__init__(name, run_every="5m")
		

	def update(self):
		feed = urllib2.urlopen("http://urlquery.net/rss.php")
		self.status = "OK"

		children = ["title", "link", "description", "pubDate"]
		main_node = "item"
		
		tree = etree.parse(feed)
		for item in tree.findall("//%s"%main_node):
			dict = {}
			for field in children:
				dict[field] = item.findtext(field)
			
			if dict['description'] != 'No alerts detected.':
				self.analyze(dict)

		return True

	def analyze(self, dict):
		
		url_re = re.compile('URL</td><td style=\'color:black;vertical-align:top;\'>(.+)</td>')
		
		exploit_kit_re = re.compile('Detected\s(.+)\sexploit\skit', re.IGNORECASE)
		iframe_re = re.compile('iframe\sinjection', re.IGNORECASE)
		cookiebomb_re = re.compile('CookieBomb', re.IGNORECASE)
		dynamicdns_re = re.compile('Dynamic\sDNS', re.IGNORECASE)
		tds_re = re.compile('TDS\sURL', re.IGNORECASE)

		page_data = urllib2.urlopen(dict['link']).read()
		self.status = "OK"

		url = url_re.findall(page_data)
		exploit_kit = exploit_kit_re.findall(page_data)
		iframe = iframe_re.findall(page_data)
		cookiebomb = cookiebomb_re.findall(page_data)
		dynamicdns = dynamicdns_re.findall(page_data)
		tds = tds_re.findall(page_data)

		if url:
			dict["link"] = url[0]
		else:
			return False
		
		tags = ['urlquery']
		
		if exploit_kit: tags.append(exploit_kit[0])
		if iframe: tags.append('iframe infection')
		if cookiebomb: tags.append('cookiebomb')
		if dynamicdns: tags.append('dynamic dns') 
		if tds: tags.append('tds')

		# Create the new url and store it in the DB
		url =Url(url=url[0], tags=tags)

		url, new = self.model.save(url, with_status=True)
		if new:
			self.elements_fetched += 1