import logging
from datetime import timedelta

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import AutonomousSystem, Hash, Url


class FutexTracker(Feed):
    default_values = {
        "frequency": timedelta(minutes=60),
        "name": "FutexTracker",
        "source": "https://futex.re/tracker/TinyTracker.csv",
        "description":
            "Provides url, hash and hosting information on various malware samples.",
        # pylint: disable=line-too-long
    }

    def update(self):

        for index, line in self.update_csv(delimiter=';',
                                           filter_row='firstseen',
                                           names=['id', 'firstseen', 'url',
                                                  'status', 'hash', 'country',
                                                  'as'],
                                           header=-1):
            self.analyze(line)

    # pylint: disable=arguments-differ
    def analyze(self, line):

        _id = line['id']
        _ = line['firstseen']
        url = line['url']
        _status = line['status']

        _hash = line['hash']

        country = line['country']
        asn = line['as']

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
        print(_hash)
        if _hash and len(_hash) > 16:
            try:
                hash_obs = Hash.get_or_create(value=_hash)
                hash_obs.add_context(context)
                hash_obs.tag(tags)
                hash_obs.add_source(self.name)
                hash_obs.active_link_to(
                    url_obs, "MD5", self.name, clean_old=False)
            except ObservableValidationError as e:
                print(_hash)
                logging.error(e)

        if asn:
            try:
                asn = asn.split(" ")[0].replace("AS", "")
                asn_obs = AutonomousSystem.get_or_create(value=asn)
                asn_obs.add_context(context)
                asn_obs.tag(tags)
                asn_obs.add_source(self.name)
                asn_obs.active_link_to(
                    url_obs, "ASN", self.name, clean_old=False)
            except ObservableValidationError as e:
                logging.error(e)
