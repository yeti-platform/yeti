import logging
from datetime import timedelta, datetime
from typing import ClassVar
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class BlocklistdeBruteforceLogin(task.FeedTask):
    _SOURCE:ClassVar['str'] = "https://lists.blocklist.de/lists/bruteforcelogin.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeBruteforceLogin",
        "description": "All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item)

    def analyze(self, item):
        ip_str = item.strip()
        obs = ipv4.IPv4(value=ip_str).save()
        obs.tag(["blocklist", "bruteforce"])

taskmanager.TaskManager.register_task(BlocklistdeBruteforceLogin)
