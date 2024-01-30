#!/usr/bin/env python
"""This class will incorporate the PhishingDatabase feed into yeti."""

from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import task
from core.schemas.observables import hostname


class PhishingDatabase(task.FeedTask):
    """This class will incorporate the PhishingDatabase feed into yeti."""

    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "PhishingDatabase",
        "description": "PhishingDatabase is a community feed of phishing URLs which are updated every 24 hours.",
    }

    _SOURCE: ClassVar[
        "str"
    ] = "https://phishing.army/download/phishing_army_blocklist_extended.txt"

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            for line in response.text.split("\n"):
                self.analyze(line.strip())

    def analyze(self, domain):
        if domain:
            obs = hostname.Hostname(value=domain).save()
            obs.add_context(self.name, {"source": self.name})
            obs.tag(["phish", "phishing_database", "blocklist"])


taskmanager.TaskManager.register_task(PhishingDatabase)
