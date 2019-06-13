import re
from datetime import timedelta
from datetime import datetime
import logging

from core.feed import Feed
from core.observables import Url, Hash
from core.errors import ObservableValidationError


class ZeusTrackerBinaries(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "ZeusTrackerBinaries",
        "source": "https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries",
        "description": "This feed shows the latest 50 ZeuS binaries URLs.",
    }

    url_re = re.compile(r"URL: (?P<url>\S+),")
    date_re = re.compile(r"\((?P<date>[0-9\-]+)\)")
    status_re = re.compile(r"status: (?P<status>[^,]+)")
    md5_re = re.compile(r"MD5 hash: (?P<md5>[a-f0-9]+)")

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        for item in self.update_xml('item',
                                    ["title", "link", "description", "guid"]):

            date_string = self.date_re.search(item['title']).group('date')
            first_seen = datetime.strptime(date_string, "%Y-%m-%d")

            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(item, first_seen)

    def analyze(self, item, context):

        md5_obs = False
        context = {}
        url_string = self.url_re.search(item['description']).group('url')
        url_string = url_string.replace('http://https://', 'https://')
        context['status'] = self.status_re.search(
            item['description']).group('status')
        context['guid'] = item['guid']
        context['source'] = self.name
        try:
            context['md5'] = self.md5_re.search(
                item['description']).group('md5')
        except AttributeError:
             pass

        if context.get('md5'):
            try:
                md5_obs = Hash.get_or_create(value=context['md5'])
                md5_obs.add_context(context)
                md5_obs.add_source(self.name)
                md5_obs.tag(['zeus', 'delivery', 'banker', 'crimeware', 'malware'])
            except ObservableValidationError as e:
                logging.error(e)

        try:
            url_obs = Url.get_or_create(value=url_string)
            url_obs.add_context(context)
            url_obs.add_source(self.name)
            url_obs.tag(['zeus', 'delivery', 'banker', 'crimeware', 'malware'])

            if context.get('md5'):
                url_obs.active_link_to(md5_obs, 'md5', self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
