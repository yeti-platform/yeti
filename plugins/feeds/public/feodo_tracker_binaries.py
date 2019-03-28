from datetime import timedelta
import logging

from core.observables import Hash
from core.feed import Feed
from core.errors import ObservableValidationError


class FeodoTrackerBinaries(Feed):

    default_values = {
        "frequency":
            timedelta(hours=24),
        "name":
            "FeodoTrackerBinaries",
        "source":
            "https://feodotracker.abuse.ch/downloads/malware_hashes.csv",
        "description":
            "Feodo Tracker Binary Feed. This feed shows a full list of known md5s.",
    }

    def update(self):
        for line in self.update_csv(delimiter=',', quotechar='"'):
            self.analyze(line)

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        first_seen, md5_hash, family = tuple(line)

        tags = []
        tags.append(family.lower())
        tags.append("blocklist")

        context = {
            "first_seen": first_seen,
            "source": self.name
        }

        try:
            hash = Hash.get_or_create(value=md5_hash.rstrip())
            hash.add_context(context)
            hash.tag(tags)

        except ObservableValidationError as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))
