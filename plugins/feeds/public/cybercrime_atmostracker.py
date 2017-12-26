from datetime import timedelta
import logging
import re

from dateutil import parser

from core.observables import Hash, Url
from core.feed import Feed
from core.errors import ObservableValidationError


class CybercrimeAtmosTracker(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "CybercrimeAtmosTracker",
        "source": "http://cybercrime-tracker.net/ccam_rss.php",
        "description": "CyberCrime Atmos Tracker - Latest 20 Atmos binaries",
    }

    def update(self):
        for item in self.update_xml(
                'item', ["title", "link", "pubDate", "description"]):
            self.analyze(item)

    def analyze(self, item):
        observable_sample = item['title']
        context_sample = {}
        context_sample['description'] = "Atmos sample"
        context_sample['date_added'] = parser.parse(item['pubDate'])
        context_sample['source'] = self.name

        link_c2 = re.search(
            "<a href[^>]+>(?P<url>[^<]+)",
            item['description'].lower()).group("url")
        observable_c2 = link_c2
        context_c2 = {}
        context_c2['description'] = "Atmos c2"
        context_c2['date_added'] = parser.parse(item['pubDate'])
        context_c2['source'] = self.name

        try:
            sample = Hash.get_or_create(value=observable_sample)
            sample.add_context(context_sample)
            sample.add_source("feed")
            sample_tags = ['atmos', 'objectives']
            sample.tag(sample_tags)
        except ObservableValidationError as e:
            logging.error(e)
            return

        try:
            c2 = Url.get_or_create(value=observable_c2)
            c2.add_context(context_c2)
            c2.add_source("feed")
            c2_tags = ['c2', 'atmos']
            c2.tag(c2_tags)
            sample.active_link_to(c2, 'c2', self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
            return
