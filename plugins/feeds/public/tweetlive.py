from datetime import timedelta
from typing import ClassVar

import pandas as pd

from core import taskmanager
from core.schemas import observable, task

MAPPING = {
    "domain": observable.ObservableType.hostname,
    "ip": observable.ObservableType.ipv4,
    "sha256": observable.ObservableType.sha256,
    "url": observable.ObservableType.url,
    "md5": observable.ObservableType.md5,
}


class TweetLive(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "TweetLive",
        "description": "This feed contains tweets",
    }
    _SOURCE: ClassVar["str"] = "https://api.tweetfeed.live/v1/today"

    def run(self):
        r = self._make_request(self._SOURCE, sort=False)

        if r:
            data = r.json()

            if not data:
                raise ValueError("No data returned")

            df = pd.DataFrame(data)
            df.fillna("")
            df["date"] = pd.to_datetime(df["date"])

            df = self._filter_observables_by_time(df, "date")

        for _, line in df.iterrows():
            self.analyze(line)

    def analyze(self, item):
        if item["type"] not in MAPPING:
            return

        obs_type = MAPPING[item["type"]]

        if not obs_type:
            raise (ValueError(f"Observable type {item['type']} not supported"))

        obs = observable.TYPE_MAPPING["observable"](
            value=item["value"], type=obs_type
        ).save()

        context = {}

        if "tweet" in item:
            context["tweet"] = item["tweet"]
        if "user" in item:
            context["user"] = item["user"]

        if item["tags"]:
            obs.tag(item["tags"])

        if context:
            obs.add_context(self.name, context)
