import logging
from dateutil import parser
from datetime import datetime, timedelta
from core.observables import Hash
from core.feed import Feed
from core.errors import ObservableValidationError

from dateutil.tz import gettz
tzinfos = {"CEST": gettz("Europe/France"), "CST": gettz("Europe/France")}

class CybercrimeAtmTracker(Feed):

    default_values = {
        'frequency': timedelta(hours=1),
        'name': 'CybercrimeAtmTracker',
        'source': 'http://atm.cybercrime-tracker.net/rss.php',
        'description': 'CyberCrime ATM Tracker - Latest 40 CnC URLS',
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        for item in self.update_xml(
                'item', ['title', 'link', 'pubDate', 'description']):

            pub_date = parser.parse(item['pubDate'], tzinfos=tzinfos)
            if self.last_run is not None:
                if since_last_run > pub_date:
                    return

            self.analyze(item, pub_date)

    def analyze(self, item, pub_date):
        observable_sample = item['title']
        context_sample = {}
        context_sample['description'] = 'ATM sample'
        context_sample['date_added'] = pub_date
        context_sample['source'] = self.name
        family = False
        if ' - ' in observable_sample:
            family, observable_sample = observable_sample.split(' - ')

        try:
            sample = Hash.get_or_create(value=observable_sample)
            sample.add_context(context_sample)
            sample.add_source(self.name)
            sample_tags = ['atm']
            if family:
                sample_tags.append(family)
            sample.tag(sample_tags)
        except ObservableValidationError as e:
            logging.error(e)
            return
