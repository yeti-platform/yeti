import logging
from datetime import timedelta, datetime

import pandas as pd

from core.config.config import yeti_config
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url


class PhishTank(Feed):
    # set default values for feed

    default_values = {
        "frequency": timedelta(hours=4),
        "name": "PhishTank",
        "source": "http://data.phishtank.com/data/%s/online-valid.csv"
        % yeti_config.get("phishtank", "key"),
        "description": "PhishTank community feed. Contains a list of possible Phishing URLs.",
    }

    # should tell yeti how to get and chunk the feed
    def update(self):
        # Using update_lines because the pull should result in
        # a list of URLs, 1 per line. Split on newline

        for index, line in self.update_csv(
            delimiter=",",
            filter_row="submission_time",
            date_parser=lambda x: pd.to_datetime(x.rsplit("+", 1)[0]),
            comment=None,
        ):
            self.analyze(line)

    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def analyze(self, line):
        tags = ["phishing", "phishtank"]

        url = line["url"]

        context = {
            "source": self.name,
            "phish_detail_url": line["phish_detail_url"],
            "submission_time": line["submission_time"],
            "verified": line["verified"],
            "verification_time": line["verification_time"],
            "online": line["online"],
            "target": line["target"],
            "date_added": datetime.utcnow(),
        }

        if url is not None and url != "":
            try:
                url = Url.get_or_create(value=url)
                url.add_context(context, dedup_list=["date_added"])
                url.add_source(self.name)
                url.tag(tags)
            except ObservableValidationError as e:
                logging.error(e)
