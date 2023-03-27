import logging
from datetime import timedelta, datetime

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import AutonomousSystem, Hash, Url


class FutexTracker(Feed):
    default_values = {
        "frequency": timedelta(minutes=60),
        "name": "FutexTracker",
        "source": "https://futex.re/tracker/TinyTracker.csv",
        "description": "Provides url, hash and hosting information on various malware samples.",
        # pylint: disable=line-too-long
    }

    def update(self):
        for index, line in self.update_csv(
            delimiter=";",
            filter_row="firstseen",
            names=["id", "firstseen", "url", "status", "hash", "country", "as"],
            header=None,
        ):
            self.analyze(line)

    # pylint: disable=arguments-differ
    def analyze(self, item):
        _id = item["id"]
        _ = item["firstseen"]
        url = item["url"]
        _status = item["status"]

        _hash = item["hash"]

        country = item["country"]
        asn = item["as"]

        tags = ["collected_by_honeypot"]
        context = {
            "source": self.name,
            "country": country,
            "date_added": datetime.utcnow(),
        }

        url_obs = None

        if url:
            try:
                url_obs = Url.get_or_create(value=url.rstrip())
                url_obs.add_context(context, dedup_list=["date_added"])
                url_obs.tag(tags)
                url_obs.add_source(self.name)
            except ObservableValidationError as e:
                logging.error(e)

        if _hash and len(_hash) > 16:
            try:
                hash_obs = Hash.get_or_create(value=_hash)
                hash_obs.add_context(context, dedup_list=["date_added"])
                hash_obs.tag(tags)
                hash_obs.add_source(self.name)
                if url_obs:
                    hash_obs.active_link_to(url_obs, "MD5", self.name, clean_old=False)
            except ObservableValidationError as e:
                logging.error(e)

        if asn:
            try:
                asn = asn.split(" ")[0].replace("AS", "")
                asn_obs = AutonomousSystem.get_or_create(value=asn)
                asn_obs.add_context(context, dedup_list=["date_added"])
                asn_obs.tag(tags)
                asn_obs.add_source(self.name)
                asn_obs.active_link_to(url_obs, "ASN", self.name, clean_old=False)
            except ObservableValidationError as e:
                logging.error(e)
