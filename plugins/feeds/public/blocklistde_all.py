import logging
from datetime import timedelta
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class BlocklistdeAll(task.FeedTask):
    SOURCE = "https://lists.blocklist.de/lists/all.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeAll",
        "description": "All IP addresses that have attacked one of our customers/servers in the last 48 hours. It's not recommended to use this feed due to the lesser amount of contextual information, it's better to use each blocklist.de feed separately.",
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
        obs.tag(["blocklist"])

taskmanager.TaskManager.register_task(BlocklistdeAll)
