import logging
from datetime import timedelta

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

        for index, line in self.update_csv(delimiter=',',
                                           filter_row='Firstseen',
                                           names=['Firstseen', 'MD5hash',
                                                  'Malware'], ):
            self.analyze(line)

    def analyze(self, line):

        first_seen = line[0]
        md5_hash = line[1]
        family = line[2]

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
