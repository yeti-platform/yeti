import datetime
from time import sleep

from core.schemas import observable
from core.schemas import task
from core import taskmanager


class FeodoTrackerIPBlockList(task.FeedTask):
    _defaults = {
        "frequency": datetime.timedelta(hours=24),
        "name": "FeodoTrackerIPBlocklist",
        "source": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description": "Feodo Tracker IP Feed. This feed shows a full list C2s.",
    }

    def run(self):
        df = self.update_csv(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            delimiter=",",
            parse_dates=["first_seen_utc"],
        )

        df.apply(self.analyze, axis=1)
        # for _, line in df.iterrows():
        #     self.analyze(line)

    # pylint: disable=arguments-differ
    def analyze(self, item):
        tags = ["c2", "blocklist"]
        tags.append(item["malware"].lower())

        context = {
            "first_seen": str(item["first_seen_utc"]),
            "last_online": item["last_online"],
            "c2_status": item["c2_status"],
            "port": item["dst_port"],
            "date_added": datetime.datetime.now(datetime.timezone.utc)
        }

        ip = item["dst_ip"]
        ip_observable = observable.Observable.find(value=ip)
        if not ip_observable:
            ip_observable = observable.Observable(value=ip, type='ip').save()
        ip_observable.add_context(
            source=self.name,
            context=context,
            skip_compare={"last_online", "date_added"})
        ip_observable.tag(tags)
