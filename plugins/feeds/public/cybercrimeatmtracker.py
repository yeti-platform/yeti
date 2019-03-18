import re
import logging
from dateutil import parser
from datetime import datetime, timedelta
from core.observables import Hash
from core.feed import Feed
from core.errors import ObservableValidationError


class CybercrimeAtmTracker(Feed):

    default_values = {
        'frequency': timedelta(hours=1),
        'name': 'CybercrimeAtmTracker',
        'source': 'http://atm.cybercrime-tracker.net/rss.php',
        'description': 'CyberCrime ATM Tracker - Latest 40 CnC URLS',
    }

    def update(self):
        for item in self.update_xml(
                'item', ['title', 'link', 'pubDate', 'description']):
            self.analyze(item)

    def analyze(self, item):
        observable_sample = item['title']
        context_sample = {}
        context_sample['description'] = 'ATM sample'
        context_sample['date_added'] = parser.parse(item['pubDate'])
        context_sample['source'] = self.name
        family = False
        if ' - ' in observable_sample:
            family, observable_sample = observable_sample.split(' - ')

        try:
            sample = Hash.get_or_create(value=observable_sample)
            sample.add_context(context_sample)
            sample.add_source('feed')
            sample_tags = ['atm']
            if family:
                sample_tags.append(family)
            sample.tag(sample_tags)
        except ObservableValidationError as e:
            logging.error(e)
            return
