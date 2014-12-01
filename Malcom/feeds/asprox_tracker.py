from Malcom.model.datatypes import Ip, Url, Hostname, As, Evil 
from Malcom.feeds.feed import Feed

import Malcom.auxiliary.toolbox as toolbox

import urllib2
from bson.json_util import dumps, loads

class AsproxTracker(Feed):
	"""
	This is a feed that will fetch data from a URL and process it
	"""
	def __init__(self, name):
		super(AsproxTracker, self).__init__(name, run_every="12h") 
		
		self.name = "AsproxTracker" 
		self.source = "http://atrack.h3x.eu/api/asprox_full_csv.php" 
		self.description = "This feed contains known Asprox C2 servers"

	def update(self):
		self.update_lines()

	def analyze(self, line):

		Number,Status,CC,Host,Port,Protocol = line.split(',')[:6] # split the entry into elements

		_url = Url(url="{}://{}:{}".format(Protocol, Host, Port))
		_url['tags'] = ['asprox']

		evil = Evil() 
		evil['tags'] = ['asprox', 'cc']
		evil['value'] = 'Asprox C2: {}'.format(_url['value'])
		evil['status'] = Status
		
		return _url, evil


