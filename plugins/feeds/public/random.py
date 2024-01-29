from datetime import timedelta

from core import taskmanager
from core.schemas import observable, task

DATA = [
    "hostname1.com",
    "hostname2.com",
    "hostname3.com",
    "hostname4.com",
    "hostname5.com",
]


class Random(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "type": "feed",
        # "source": "https://bazaar.abuse.ch/export/csv/recent/",
        "description": "This feed contains md5/sha1/sha256",
    }

    def run(self):
        for item in DATA:
            print(item)
            observable.Observable.add_text(item)


taskmanager.TaskManager.register_task(Random)
