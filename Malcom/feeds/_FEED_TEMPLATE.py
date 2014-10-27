
# Import the datatypes so that you can add Ips, Urls, Hostnames, or whatever it is your feed is supposed to fetch.
from Malcom.model.datatypes import Ip, Url, Hostname, As, Evil 
# This is the base Feed class to inherit from.
from Malcom.feeds.feed import Feed
# The 'toolbox' module contains useful methods like searching for IP addresses or hostnames in raw text.
import Malcom.auxiliary.toolbox as toolbox

import urllib2 # use this fo tech HTTP / HTTPs resources.
from bson.json_util import dumps, loads # You'll probably end-up using this if you need to parse JSON responses.

class MalcomFeedTemplate(Feed):
	"""
	This is a feed that will fetch data from a URL and process it
	"""
	def __init__(self, name):
		# The 'run_every' parameter defines how often the feed is run.
		# Values are defined with 'd' for days, 'h' for hours, 'm' for minutes, 's' for seconds.
		super(MalcomFeedTemplate, self).__init__(name, run_every="12h") 
		
		# This is the name of your feed. That's how it will show up on the feed page.
		self.name = "My Demo feed" 
		
		# This is the URL that the feed will request for fetching the data.
		self.source = "http://data.source.com/source.php?id=asd" 
		
		# This is what the source is about, keep it as accurate as possible.
		# Useful when you need to know precisely where the info comes from and what it means.
		self.description = "This feed contains known Zeus CC servers seen in the last 24h"

	def update(self):
		# 	This is the method that will connect to the url defined in self.source and fetch data. Odds are you'll mostly be parsing
		# 	XML or CSV files. You can call one of Malcom's built-in functions to help:

		# 			self.update_xml('main_node', ['child_node1, child_node2, child_node3'])

		# 	Is used to parse basic XML data. 'main_node' is the XML node containing one informaiton record. "child_nodeX"
		# 	is the node containing the actual data. This provides the analyze() function with a dictionary that can be
		# 	accessed with dict['child_nodeX']. Take a look at zeusconfigs.py for a concrete example.

		# 			self.update_lines()

		# 	This one is used to feed the analyze() function with one line of data at a time. Useful when you need to parse
		# 	CSV / TSV records or any record that fits in one line. A concrete example of this can be found in alienvault.py

		self.update_xml("main_node", ['child_node1', 'child_node2', 'child_node3'])

		# or alternatively

		self.lines()

		# If you're not dealing with XML or single-line formatted data, you can always manually parse the file yourself
		# To do this, just don't use self.update_xml or self.lines - fetch the data yourself and feed it record-by-record
		# to the analyze function. Take a look at the torexitnodes.py file for an example of this.

	def analyze(self, line):
		# This function should only analyze one record at a time (i.e. one line, or one XML node)
		# This is also where you tell Malcom to ignore e.g. lines starting with #
		#
		# Say the resource you requested has the following format:
		#
		# 	ip_addr;owner;description;
		# 	8.8.8.8;Google Inc.;malicious nameserver;
		#
		# You should a script similar to:

		ip, org, description = line.split(';') # split the entry into elements
		_ip = Ip(ip=ip) # create a new IP element.
		_ip['tags'] = ['google.com'] # add any tags you want. the 'evil' tag will be added automatically before insert

		# Now comes the definition of the Evil element. Associate it with other elements to build threat intel.
		# Not adding the information directly to the IP element enables us to determine how many different sources have
		# seen this specific artifact.

		evil = Evil() 
		evil['tags'] = ['zeus', 'cc'] # it was a Zeus CC, remember the feed description?

		# If you're using a helper function like update_xml or lines, the return value of the analyze function must always
		# be a tuple of type (Element, Evil). This will connect both elements, add apropriate tags to them and insert them
		# in the db. 
		
		return _ip, evil


