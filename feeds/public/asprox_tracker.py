import urllib2
from datetime import datetime, timedelta
import csv

from core.db.datatypes import Url
from core.feed import Feed

class AsproxTracker(Feed):

    settings = {
        "frequency": timedelta(hours=1),
        "name": "AsproxTracker",
        "source": "http://atrack.h3x.eu/api/asprox_full_csv.php",
        "description": "This feed contains known Asprox C2 servers",
    }

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

        url = "{}://{}".format(Protocol, Host)
        context = {}
        context['status'] = Status
        context['port'] = Port
        context['cc'] = CC
        context['status'] = Status
        context['date_added'] = datetime.strptime(First_Seen, "%Y-%m-%d %H:%M:%S")
        context['last_seen'] = datetime.strptime(Last_Seen, "%Y-%m-%d %H:%M:%S") if Last_Seen else datetime.utcnow()
        context['sbl'] = SBL
        context['abuse_contact'] = Abuse_Contact
        context['description'] = Details if Details else "N/A"
        context['source'] = self.name
        try:
            url = Url.get_or_create(url)
            url.add_context(context)
            url.tag(['asprox', 'c2', 'scanner'])
        except ValueError as e:
            logging.error('Invalid URL: {}'.format(url_string))
