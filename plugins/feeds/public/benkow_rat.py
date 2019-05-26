import requests
from datetime import datetime, timedelta
import csv
import logging

from core.observables import Url, Ip
from core.feed import Feed
from core.errors import ObservableValidationError
from core.config.config import yeti_config
from core.errors import GenericYetiError

class BenkowTrackerRat(Feed):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "BenkowTrackerRat",
        "source" : "http://benkow.cc/export_rat.php",
        "description": "This feed contains known Malware C2 servers",
    }

    def update(self):
        resp = requests.get(self.source, proxies=yeti_config.proxy)
        if not resp.ok:
            raise GenericYetiError("{} - got response code {}".format(self.name, resp.status_code))
        
        reader = csv.reader(resp.content.strip().splitlines(), delimiter=';', quotechar='"')
        for line in reader:
            self.analyze(line)

    def analyze(self, line):
        if line[0] == 'id':
            return

        id, family, url, ip, first_seen, _ = line
        if not url.startswith(('http://', 'https://')):
            url = "http://"+url

        context = {}
        context['date_added'] = first_seen
        context['source'] = self.name

        tags = []
        tags.append(Family.lower())
        tags.append("rat")

        try:
            if  url:
                url = Url.get_or_create(value=url)
                url.add_context(context)
                url.add_source(self.name)
                url.tag(tags)

        except ObservableValidationError as e:
            logging.error(e)

        try:
            if ip:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source(self.name)
                ip.tag(tags)

        except ObservableValidationError as e:
            logging.error(e)
