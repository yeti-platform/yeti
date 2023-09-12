import logging
from datetime import timedelta
from core.schemas.observables import ipv4
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
        response = self._make_request(self.SOURCE)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item)

    def analyze(self, item):
        ip_str = item.strip()

        obs = ipv4.IPv4.find(value=ip_str)
        if not obs:
            obs = ipv4.IPv4(value=ip_str).save()
            
        obs.tag(["blocklist", "sip"])


taskmanager.TaskManager.register_task(BlocklistdeSIP)
