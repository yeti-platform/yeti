import logging
from datetime import timedelta, datetime
from core.schemas import observable
from core.schemas import task
from core import taskmanager


class BlocklistdeSIP(task.FeedTask):
    SOURCE = "https://lists.blocklist.de/lists/sip.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeSIP",
        "description": "All IP addresses which have been reported within the last 48 hours for attacks on the Service SIP.",
    }

    def run(self):
        response = self._make_request(self.SOURCE, verify=True)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item)

    def analyze(self, item):
        ip = item.strip()

        obs = observable.Observable.find(value=ip)
        if not obs:
            obs = observable.Observable(value=ip, type="ip").save()

        obs.tag(["blocklist", "sip"])


taskmanager.TaskManager.register_task(BlocklistdeSIP)
