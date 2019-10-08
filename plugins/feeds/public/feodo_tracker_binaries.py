import logging
from datetime import datetime, timedelta

from dateutil import parser

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Hash


class FeodoTrackerBinaries(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "FeodoTrackerBinaries",
        "source": "https://feodotracker.abuse.ch/downloads/malware_hashes.csv",
        "description":
            "Feodo Tracker Binary Feed. This feed shows a full list of known md5s.",
    }

    def update(self):

        since_last_run = datetime.utcnow() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar='"'):
            if not line or line[0].startswith("#"):
                continue

            first_seen = parser.parse(line[0])

            if self.last_run is not None:
                if since_last_run > first_seen:
                    continue

            self.analyze(line, first_seen)

    def analyze(self, line, first_seen):

        _, md5_hash, family = line

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
