import logging
from datetime import timedelta, datetime

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Hash

TYPE_DICT = {
    "MITM": ["mitm"],
    "C&C": ["c2"],
    "distribution": ["payload_delivery"],
    "sinkhole": ["sinkhole"],
}


class SSLBlackListCerts(Feed):
    default_values = {
        "frequency": timedelta(hours=24),
        "name": "SSLBlackListCerts",
        "source": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        "description": "SSLBL SSL Certificate Blacklist (SHA1 Fingerprints)",
    }

    def update(self):
        for index, line in self.update_csv(
            delimiter=",",
            names=["Listingdate", "SHA1", "Listingreason"],
            filter_row="Listingdate",
            header=8,
        ):
            self.analyze(line)

    def analyze(self, line):
        first_seen = line["Listingdate"]
        _sha1 = line["SHA1"]
        reason = line["Listingreason"]

        tags = []
        tag = reason.split(" ")
        if len(tag) >= 2:
            family = tag[0]
            tags.append(family.lower())
        _type = tag[-1]

        if TYPE_DICT.get(_type):
            tags += TYPE_DICT[_type]

        tags.append("ssl_fingerprint")

        context_hash = {
            "source": self.name,
            "first_seen": first_seen,
            "date_added": datetime.utcnow(),
        }

        try:
            sha1 = Hash.get_or_create(value=_sha1)
            sha1.tag(tags)
            sha1.add_context(context_hash)
        except ObservableValidationError as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))
