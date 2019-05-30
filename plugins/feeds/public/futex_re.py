import csv
import logging
import requests
from dateutil import parser
from datetime import timedelta, datetime
from core.feed import Feed
from core.observables import Url, Observable, Hash, AutonomousSystem
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

        since_last_run = datetime.utcnow() - self.frequency

        resp = self._make_request(proxies=yeti_config.proxy)
        reader = csv.reader(resp.content.strip().splitlines(), delimiter=';', quotechar='"')
        for line in reader:
            if not line or line[0].startswith("#"):
                continue

            _id, first_seen, url, _status, _hash, country, asn = tuple(line)
            first_seen = parser.parse(first_seen)

            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(line, url, _hash, asn)

    def analyze(self, line, url, _hash, asn):

        tags = ["collected_by_honeypot"]
        context = {
            "source": self.name
        }

        if url:
            try:
                url_obs = Url.get_or_create(value=url.rstrip())
                url_obs.add_context(context)
                url_obs.tag(tags)
                url_obs.add_source(self.name)
            except ObservableValidationError as e:
                logging.error(e)

        if _hash:
            try:
                hash_obs = Hash.get_or_create(value=_hash)
                hash_obs.add_context(context)
                hash_obs.tag(tags)
                hash_obs.add_source(self.name)
                hash_obs.active_link_to(
                    url_obs, "hash", self.name, clean_old=False)
            except ObservableValidationError as e:
                logging.error(e)

        if asn:
            try:
                asn = asn.split(" ")[0].replace("AS", "")
                asn_obs = AutonomousSystem.get_or_create(value=asn)
                asn_obs.add_context(context)
                asn_obs.tag(tags)
                asn_obs.add_source(self.name)
                asn_obs.active_link_to(
                    url_obs, "asn", self.name, clean_old=False)
            except ObservableValidationError as e:
                logging.error(e)
