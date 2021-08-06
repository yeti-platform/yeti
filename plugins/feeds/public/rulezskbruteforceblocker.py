import logging
from datetime import datetime, timedelta

from dateutil import parser
import pandas as pd
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip


class RulezSKBruteforceBlocker(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "RulezSKBruteforceBlocker",
        "source": "http://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        "description": "This feed contains daily list of IPs from rules.sk",
    }

    def update(self):

        r = self._make_request(headers={"User-Agent": "yeti-project"})
        if r.status_code == 200:
            content = [
                l.split("\t") for l in r.text.split("\n") if not l.startswith("#") and l
            ]
            df = pd.DataFrame(content)
            df.drop([1, 3], axis=1, inplace=True)
            df.columns = ["ip", "last_report", "count", "id"]
            df["last_report"] = df["last_report"].str.replace("# ", "")
            df["last_report"] = df["last_report"].apply(lambda x: parser.parse(x))
            if self.last_run:
                df = df[df["last_report"] > self.last_run]
            for ix, row in df.iterrows():
                self.analyze(row)

    def analyze(self, row):
        context = {}
        context["first_seen"] = row["last_report"]
        context["source"] = self.name
        context["count"] = row["count"]
        context["id"] = row["id"]
        ip = row["ip"]
        try:
            ip = Ip.get_or_create(value=ip)
            ip.add_context(context)
            ip.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)
