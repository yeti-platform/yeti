from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import task
from core.schemas.observables import ipv4


class BlocklistdeIMAP(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://lists.blocklist.de/lists/imap.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeIMAP",
        "description": "All IP addresses which have been reported within the last 48 hours for attacks on the Service IMAP.",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item)

    def analyze(self, item):
        ip_str = item.strip()

        context = {"source": self.name}

        if ip_str:
            obs = ipv4.IPv4(value=ip_str).save()
            obs.add_context(self.name, context)
            obs.tag(["blocklist", "imap"])


taskmanager.TaskManager.register_task(BlocklistdeIMAP)
