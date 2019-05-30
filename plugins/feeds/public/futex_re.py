import csv
import logging
import requests
from dateutil import parser
from datetime import timedelta
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
        resp = requests.get(self.source, proxies=yeti_config.proxy)
        if resp.ok:
            reader = csv.reader(resp.content.strip().splitlines(), delimiter=';', quotechar='"')
            for line in reader:
                self.analyze(line)


    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return
        else:

            _id, date, url, _status, _hash, country, asn = tuple(line)
            tags = ["collected_by_honeypot"]
            context = {
                "first_seen": parser.parse(date),
                "source": self.name
            }

            if url:
                try:
                    url = Url.get_or_create(value=url.rstrip())
                    url.add_context(context)
                    url.tag(tags)
                except ObservableValidationError as e:
                    logging.error(e)

            if _hash:
                try:
                    hash = Hash.get_or_create(value=_hash)
                    hash.add_context(context)
                    hash.tag(tags)
                    hash.active_link_to(
                        url, "hash", self.name, clean_old=False)
                except ObservableValidationError as e:
                    logging.error(e)

            if asn:
                try:
                    import csv
import logging
import requests
from dateutil import parser
from datetime import timedelta
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
        resp = requests.get(self.source, proxies=yeti_config.proxy)
        if resp.ok:
            reader = csv.reader(resp.content.strip().splitlines(), delimiter=';', quotechar='"')
            for line in reader:
                self.analyze(line)


    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return
        else:

            _id, date, url, _status, _hash, country, asn = tuple(line)
            tags = ["collected_by_honeypot"]
            context = {
                "first_seen": parser.parse(date),
                "source": self.name
            }

            if url:
                try:
                    url = Url.get_or_create(value=url.rstrip())
                    url.add_context(context)
                    url.tag(tags)
                except ObservableValidationError as e:
                    logging.error(e)

            if _hash:
                try:
                    hash = Hash.get_or_create(value=_hash)
                    hash.add_context(context)
                    hash.tag(tags)
                    hash.active_link_to(
                        url, "hash", self.name, clean_old=False)
                except ObservableValidationError as e:
                    logging.error(e)

            if asn:
                try:
                    asn = asn.split(" ")[0].replace("AS", "")
                    asn_obs = AutonomousSystem.get_or_create(value=asn)
                    asn_obs.add_context(context)
                    asn_obs.tag(tags)
                    asn_obs.active_link_to(
                        url, "asn", self.name, clean_old=False)
                except ObservableValidationError as e:
                    logging.error(e)

                    asn_obs = AutonomousSystem.get_or_create(value=asn)
                    asn_obs.add_context(context)
                    asn_obs.tag(tags)
                    asn_obs.active_link_to(
                        url, "asn", self.name, clean_old=False)
                except ObservableValidationError as e:
                    logging.error(e)
