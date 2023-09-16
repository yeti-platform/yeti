import logging
from datetime import timedelta, datetime
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class BlocklistdeIMAP(task.FeedTask):
    SOURCE = "https://lists.blocklist.de/lists/imap.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeIMAP",
        "description": "All IP addresses which have been reported within the last 48 hours for attacks on the Service IMAP.",
    }

    def run(self):
        response = self._make_request(self.SOURCE)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item)

    def analyze(self, item):
        ip_str = item.strip()
        obs = ipv4.IPv4(value=ip_str).save()
        obs.tag(["blocklist", "imap"])


taskmanager.TaskManager.register_task(BlocklistdeIMAP)
