#!/usr/bin/env python
"""This class will incorporate the PhishingDatabase feed into yeti."""

from datetime import timedelta
from core.schemas.observables import url
from core.schemas import task
from core import taskmanager


class PhishingDatabase(task.FeedTask):
    """This class will incorporate the PhishingDatabase feed into yeti."""

    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "PhishingDatabase",
        "description": "PhishingDatabase is a community feed of phishing URLs which are updated every 24 hours.",
    }

    SOURCE = "https://phishing.army/download/phishing_army_blocklist_extended.txt"

    def run(self):
        response = self._make_request(self.SOURCE)
        if response:
            for line in response.text.split("\n"):
                self.analyze(line.strip())
           

    def analyze(self, url_str):
        context = {"source": self.name}

        urlobs = url.Url.find(value=url_str)
        if not urlobs:
            urlobs = url.Url(value=url_str).save()
        urlobs.add_context(self.name, context)
        urlobs.tag(["phish","phishing_database","blocklist"])
    
taskmanager.TaskManager.register_task(PhishingDatabase)

        
