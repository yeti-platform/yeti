from io import StringIO
import logging
from datetime import timedelta, datetime

import pandas as pd

from core.config.config import yeti_config
from core.schemas.observables import url
from core.schemas import task
from core import taskmanager


class PhishTank(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "PhishTank",
        "description": "PhishTank is a collaborative clearing house for data and information about phishing on the Internet.",
    }

    SOURCE = "http://data.phishtank.com/data/%s/online-valid.csv"

    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def run(self):
        key_phishtank = yeti_config.get("phishtank", "key")
        assert key_phishtank, "PhishTank key not configured in yeti.conf"

        response = self._make_request(self.SOURCE % key_phishtank)
        if response:
            data = response.text

            df = pd.read_csv(
                StringIO(data),
                delimiter=",",
                date_parser=lambda x: pd.to_datetime(x.rsplit("+", 1)[0]),
                comment=None,
                parse_dates=["submission_time"],
            )
            df.fillna("", inplace=True)

            df = self._filter_observables_by_time(df, "submission_time")
            for _, line in df.iterrows():
                self.analyze(line)

    def analyze(self, line):
        tags = ["phishing", "phishtank"]

        url_str = line["url"]

        context = {
            "source": self.name,
            "phish_detail_url": line["phish_detail_url"],
            "submission_time": line["submission_time"],
            "verified": line["verified"],
            "verification_time": line["verification_time"],
            "online": line["online"],
            "target": line["target"],
        }

        if url_str is not None and url_str != "":
            url_obs = url.Url(value=url_str).save()
            url_obs.add_context(self.name, context)
            url_obs.tag(tags)


taskmanager.TaskManager.register_task(PhishTank)
