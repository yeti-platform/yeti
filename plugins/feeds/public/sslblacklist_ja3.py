from datetime import timedelta
from io import StringIO
from typing import ClassVar

import pandas as pd

from core import taskmanager
from core.schemas import task
from core.schemas.observables import ja3


class SSLBlacklistJA3(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "SSLBlacklistJA3",
        "description": "This feed contains JA3 hashes of SSL by AbuseCH",
    }

    _SOURCE: ClassVar["str"] = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
    _NAMES = ["ja3_md5", "first_seen", "last_seen", "threat"]

    def run(self):
        response = self._make_request(self._SOURCE, auth=None, verify=True)
        if response:
            data = StringIO(response.text)

            df = pd.read_csv(
                data,
                delimiter=",",
                comment="#",
                names=self._NAMES,
                parse_dates=["first_seen"],
            )
            df = self._filter_observables_by_time(df, "last_seen")
            df = df.fillna("")
            for _, row in df.iterrows():
                self.analyze(row)

    def analyze(self, row):
        ja3_md5 = row["ja3_md5"]
        first_seen = row["first_seen"]
        last_seen = row["last_seen"]
        threat = row["threat"]

        ja3_obs = ja3.JA3(value=ja3_md5).save()

        context = {}
        context["first_seen"] = first_seen
        context["last_seen"] = last_seen

        ja3_obs.add_context(self.name, context)

        if threat:
            ja3_obs.tag([threat])


taskmanager.TaskManager.register_task(SSLBlacklistJA3)
