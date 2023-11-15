import logging
from datetime import timedelta, datetime
from typing import ClassVar
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class BlocklistdeIRCBot(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://lists.blocklist.de/lists/ircbot.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeIRCBot",
        "description": "All IP addresses which have been reported within the last 48 hours for attacks on the Service IRC.",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item)

    def analyze(self, item):
        ip_str = item.strip()
        if ip_str:
            obs = ipv4.IPv4(value=ip_str).save()
            obs.tag(["blocklist", "irc"])


taskmanager.TaskManager.register_task(BlocklistdeIRCBot)
