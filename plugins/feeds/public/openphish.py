from datetime import timedelta
import logging
import traceback
from typing import ClassVar

from core.schemas.observables import url
from core.schemas import task
from core import taskmanager


class OpenPhish(task.FeedTask):
    # set default values for feed
    _SOURCE: ClassVar["str"] = "https://openphish.com/feed.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "OpenPhish",
        "description": "OpenPhish is a community feed of phishing URLs which are updated every 24 hours.",
    }

    # run() is the main function that is called by the scheduler
    # it is the main entry point into the feed
    def run(self):
        # make a request to the feed URL
        response = self._make_request(self._SOURCE)
        if response:
            # iterate over the lines in the response and analyze each one
            for line in response.text.split("\n"):
                self.analyze(line)

    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def analyze(self, url_str):
        context = {"source": self.name}

        # check to see if the URL is already in the database
        # if it is, then we don't need to do anything
        # if it isn't, then we need to add it
        if not url_str:
            return
        obs = url.Url(value=url_str).save()
        obs.add_context(self.name, context)
        obs.tag(["phish"])


taskmanager.TaskManager.register_task(OpenPhish)
