from datetime import timedelta, datetime
import logging
import traceback

from core.schemas import observable
from core.schemas import task
from core import taskmanager


class OpenPhish(task.FeedTask):
    # set default values for feed
    SOURCE = "https://openphish.com/feed.txt"
    _default = {
        "frequency": timedelta(hours=1),
        "name": "OpenPhish",
        "description": "OpenPhish is a community feed of phishing URLs which are updated every 24 hours.",
    }

    # run() is the main function that is called by the scheduler
    # it is the main entry point into the feed
    def run(self):
        # make a request to the feed URL
        response = self._make_request(self.SOURCE, verify=True)
        if response:
            # iterate over the lines in the response and analyze each one
            for line in response.text.split("\n"):
                self.analyze(line)
    
    # don't need to do much here; want to add the information
    # and tag it with 'phish'
    def analyze(self, url):
        context = {"source": self.name}

        # check to see if the URL is already in the database
        # if it is, then we don't need to do anything
        # if it isn't, then we need to add it
        try:
            obs = observable.Observable.find(value=url)
            if not obs:
                obs = observable.Observable(value=url, type="url").save()

            # add the context to the observable
            obs.add_context(self.name, context)

            # tag the observable with 'phish'
            obs.tag(["phish"])
        except Exception as e:
            logging.error(traceback.format_exc())
            raise RuntimeError("Error analyzing URL: {}".format(url))

taskmanager.TaskManager.register_task(OpenPhish)