from datetime import datetime, timedelta
import logging
import re
from dateutil import parser
from core.observables import Hash, Url
from core.feed import Feed
from core.errors import ObservableValidationError


class CybercrimePonyTracker(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "CybercrimePonyTracker",
        "source": "http://cybercrime-tracker.net/ccpm_rss.php",
        "description": "CyberCrime Pony Tracker - Latest 20 CnC URLS",
    }

    def update(self):
        for dict in self.update_xml('item', ["title", "link", "pubDate", "description"]):
            self.analyze(dict)

    def analyze(self, dict):
        observable_sample = dict['title']
        context_sample = {}
        context_sample['description'] = "Pony sample"
        context_sample['date_added'] = parser.parse(dict['pubDate'])
        context_sample['source'] = self.name

        link_c2 = re.search("https?://[^ ]*", dict['description'].lower()).group()
        observable_c2 = link_c2
        context_c2 = {}
        context_c2['description'] = "Pony c2"
        context_c2['date_added'] = parser.parse(dict['pubDate'])
        context_c2['source'] = self.name

        try:
            sample = Hash.get_or_create(value=observable_sample)
            sample.add_context(context_sample)
            sample.add_source("feed")
            sample_tags = ['pony', 'objectives']
            sample.tag(sample_tags)
        except ObservableValidationError as e:
            logging.error(e)
            return

        try:
            c2 = Url.get_or_create(value=observable_c2)
            c2.add_context(context_c2)
            c2.add_source("feed")
            c2_tags = ['c2', 'pony']
            c2.tag(c2_tags)
            sample.active_link_to(c2, 'c2', self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
            return
