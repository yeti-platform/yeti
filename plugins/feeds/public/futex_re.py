import csv
import logging
import requests
from dateutil import parser
from datetime import timedelta
from core.feed import Feed
from core.observables import Url, Ip, Observable, Hash, AutonomousSystem
from core.errors import ObservableValidationError
from core.config.config import yeti_config

class FutexTracker(Feed):

    default_values = {
        "frequency": timedelta(minutes=60),
        "name": "FutexTracker",
        "source": "https://futex.re/tracker/TinyTracker.csv",
        "description":
            "Provides url, hash and hosting information on various malware samples.",
    }

    def update(self):
        resp = requests.get(self.source, proxies=yeti_config.proxy)
        if resp.ok:
            reader = csv.reader(resp.content.strip().splitlines(), delimiter=';' ,quotechar='"')
            for line in reader:
                self.analyze(line)


    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return
        else:
            try:
                _id, date, url, _status, _hash, country, asn = tuple(line)

                tags = ["collected_by_honeypot"]

                context = {
                    "first_seen": parser.parse(date),
                    "source": self.name
                }

                if url:
                    url = Url.get_or_create(value=url.rstrip())
                    url.add_context(context)
                    url.tag(tags)

                if _hash:
                    hash = Hash.get_or_create(value=_hash)
                    hash.add_context(context)
                    hash.tag(tags)

                if asn:
                    asn_obs = AutonomousSystem.get_or_create(value=asn)
                    asn_obs.add_context(context)
                    asn_obs.tag(tags)

            except Exception as e:
                logging.error("Invalid line: {}\nLine: {}".format(e, line))
