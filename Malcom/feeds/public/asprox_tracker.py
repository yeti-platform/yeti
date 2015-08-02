import md5
import urllib2
import datetime
import csv

from Malcom.model.datatypes import Url
from Malcom.feeds.core import Feed


class AsproxTracker(Feed):
    """
    This is a feed that will fetch data from a URL and process it
    """
    def __init__(self):
        super(AsproxTracker, self).__init__(run_every="12h")

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

        # split the entry into elements
        Number, Status, CC, Host, Port, Protocol, ASN, Last_Updated, First_Seen, Last_Seen, First_Active, Last_Active, SBL, Abuse_Contact, Details = line

        url = Url(url="{}://{}:{}".format(Protocol, Host, Port))
        url['tags'] = ['asprox']

        evil = {}

        evil['status'] = Status
        evil['cc'] = CC
        evil['status'] = Status
        evil['date_added'] = datetime.datetime.strptime(First_Seen, "%Y-%m-%d %H:%M:%S")
        evil['last_seen'] = datetime.datetime.strptime(Last_Seen, "%Y-%m-%d %H:%M:%S") if Last_Seen else datetime.datetime.utcnow()
        evil['sbl'] = SBL
        evil['abuse_contact'] = Abuse_Contact
        evil['description'] = Details if Details else "N/A"
        evil['id'] = md5.new(First_Seen+Host).hexdigest()
        evil['source'] = self.name

        url.seen(first=evil['date_added'], last=evil['last_seen'])
        url.add_evil(evil)
        self.commit_to_db(url)
