import re
from core.feed import BaseFeed
from core.db.datatypes import Url
from datetime import timedelta

class ZeusTrackerConfigs(BaseFeed):

    FREQUENCY = timedelta(seconds=2)

    def __init__(self):
        self.name = "ZeusTrackerConfigs"
        self.source = "https://zeustracker.abuse.ch/monitor.php?urlfeed=configs"
        self.description = "This feed shows the latest 50 ZeuS config URLs."

    def update(self):
        for d in self.update_xml('item', ["title", "link", "description", "guid"]):
            self.analyze(d)

    def analyze(self, dict):
        url_string = re.search(r"URL: (?P<url>\S+),", dict['description']).group('url')
        context = {'type': "c2", "family": "zeus"}
        n = Url.add_context(url_string, self.name, context)

    def test(self):
        print "Test: ", self.name
