import logging
from datetime import timedelta
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class BlocklistdeApache(task.FeedTask):
    SOURCE = "https://lists.blocklist.de/lists/apache.txt"

    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeApache",
        "description": "All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.",
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
        obs.tag(["blocklist", "apache"])


taskmanager.TaskManager.register_task(BlocklistdeApache)
