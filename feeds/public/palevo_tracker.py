import re
from datetime import datetime, timedelta

from core.feed import Feed
from core.observables import Hostname

class PalevoTracker(Feed):

    settings = {
        "frequency": timedelta(hours=1),
        "name": "PalevoTracker",
        "source": "https://palevotracker.abuse.ch/?rssfeed",
        "description": "List of the twenty most recent Palevo Botnet C2 servers Palevo Tracker came across of.",
    }

    def update(self):
        for dict in self.update_xml('item', ["title", "link", "description", 'guid']):
            self.analyze(dict)

    def analyze(self, dict):

        hostname, date_string = dict['title'].split(' ')

        context = dict
        context['source'] = self.name
        context['status'] = re.search(r"Status: (?P<status>\S+)", dict['description']).group('status')
        context['date_added'] = datetime.strptime(date_string, "%Y-%m-%d")
        try:
            context['SBL'] = re.search(r"SBL: (?P<sbl>\S+),", dict['description']).group('sbl')
        except AttributeError as e:
            pass
        context['description'] = "Palevotracker C2"
        try:
            context['status'] = re.search(r"Status: (?P<status>\S+),", dict['description']).group('status')
        except AttributeError as e:
            pass

        try:
            hn = Hostname.get_or_create(hostname)
            hn.add_context(context)
            hn.tag(['palevo', 'c2', 'malware', 'crimeware', 'worm'])
        except ValidationError as e:
            logging.error('Invalid Hostname: {}'.format(hostname))
