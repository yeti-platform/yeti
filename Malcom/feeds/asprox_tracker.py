import md5
import urllib2
import datetime
import StringIO
import csv

from bson.json_util import dumps, loads

from Malcom.model.datatypes import Ip, Url, Hostname, As
from Malcom.feeds.feed import Feed
import Malcom.auxiliary.toolbox as toolbox



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
		request = urllib2.Request(self.source)
		reader = csv.reader(urllib2.urlopen(request), delimiter=',', quotechar="'")
		for line in reader:
			self.analyze(line)

	def analyze(self, line):

		if line[0] == 'Number':
			return

		Number,Status,CC,Host,Port,Protocol, ASN, Last_Updated, First_Seen, Last_Seen, First_Active, Last_Active, SBL, Abuse_Contact, Details = line # split the entry into elements

		url = Url(url="{}://{}:{}".format(Protocol, Host, Port))
		url['tags'] = ['asprox']

		evil = {}

		evil['status'] = Status
		evil['cc'] = CC
		evil['status'] = Status
		print First_Seen
		evil['date_added'] = datetime.datetime.strptime(First_Seen, "%Y-%m-%d %H:%M:%S")
		print Last_Seen
		evil['last_seen'] = datetime.datetime.strptime(Last_Seen, "%Y-%m-%d %H:%M:%S") if Last_Seen else datetime.datetime.utcnow()
		evil['sbl'] = SBL
		evil['abuse_contact'] = Abuse_Contact
		evil['description'] = Details if Details else "N/A"
		evil['id'] = md5.new(First_Seen+Host).hexdigest()
		evil['source'] = self.name

		url.seen(first=evil['date_added'], last=evil['last_seen'])
		url.add_evil(evil)
		self.commit_to_db(url)


