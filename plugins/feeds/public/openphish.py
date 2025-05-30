import logging
from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import observable, task


class OpenPhish(task.FeedTask):
    # set default values for feed
    _SOURCE: ClassVar["str"] = (
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    )
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
        try:
            obs = observable.save(type="url", value=url_str, tags=["phish"])
            obs.add_context(self.name, context)
        except Exception:
            self.logger.exception(f"Failed to save URL: {url_str}")


taskmanager.TaskManager.register_task(OpenPhish)
