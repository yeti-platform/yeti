import logging
import re
from datetime import timedelta, datetime

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url, Hash


class ZeusTrackerDropzones(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "ZeusTrackerDropzones",
        "source": "https://zeustracker.abuse.ch/monitor.php?urlfeed=dropzones",
        "description": "Shows the latest 50 ZeuS dropzone URLs.",
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
                    continue

            self.analyze(item, first_seen)

    def analyze(self, item, first_seen):

        md5_obs = False

        context = {}
        context['date_added'] = first_seen
        context['status'] = self.status_re.search(
            item['description']).group('status')
        context['guid'] = item['guid']
        context['source'] = self.name
        try:
            context['md5'] = self.md5_re.search(
                item['description']).group('md5')
        except AttributeError:
            pass

        url_string = self.url_re.search(item['description']).group('url')

        if context.get('md5'):
            try:
                md5_obs = Hash.get_or_create(value=context['md5'])
                md5_obs.add_context(context)
                md5_obs.add_source(self.name)
                md5_obs.tag(['zeus', 'banker', 'crimeware', 'malware'])
            except ObservableValidationError as e:
                logging.error(e)

        try:
            url_obs = Url.get_or_create(value=url_string)
            url_obs.add_context(context)
            url_obs.add_source("feed")
            url_obs.tag(['zeus', 'objective', 'banker', 'crimeware', 'malware'])
            if md5_obs:
                url_obs.active_link_to(md5_obs, 'md5', self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
