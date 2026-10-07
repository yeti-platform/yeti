from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import observable, task


class Phishunt(task.FeedTask):
    # set default values for feed
    _SOURCE: ClassVar["str"] = "https://phishunt.io/feed.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "Phishunt",
        "description": "phishunt.io is a public feed of phishing URLs. It is updated every hour and released under CC0 1.0 (no API key needed).",
    }

    # run() is the main function that is called by the scheduler
    # it is the main entry point into the feed
    def run(self):
        # make a request to the feed URL
        response = self._make_request(self._SOURCE)
        if response:
            # the feed is plain text with one URL per line
            for line in response.text.splitlines():
                self.analyze(line)

    # add the URL as an observable and tag it with 'phish' and 'phishunt'
    def analyze(self, url_str):
        context = {"source": self.name}

        # skip blank lines and comments
        url_str = url_str.strip()
        if not url_str or url_str.startswith("#"):
            return
        try:
            obs = observable.save(type="url", value=url_str, tags=["phish", "phishunt"])
            obs.add_context(self.name, context)
        except Exception:
            self.logger.exception(f"Failed to save URL: {url_str}")


taskmanager.TaskManager.register_task(Phishunt)
