import logging
from datetime import timedelta, datetime
from core.schemas import observable
from core.schemas import task
from core import taskmanager


class BlocklistdeBruteforceLogin(task.FeedTask):
    URL_FEED = "https://lists.blocklist.de/lists/bruteforcelogin.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeBruteforceLogin",
        "description": "All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.",
    }

    def run(self):
        response = self._make_request(self.URL_FEED, verify=True)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item)

    def analyze(self, item):
        ip = item.strip()

        context = {"source": self.name, "date_added": datetime.utcnow()}

        try:
            obs = observable.Observable.find(value=ip)
            if not obs:
                obs = observable.Observable(value=ip, type="ip").save()
            obs.add_context(self.name, context)
            obs.tag(["blocklist", "bruteforce"])
        except Exception as e:
            logging.error(e)


taskmanager.TaskManager.register_task(BlocklistdeBruteforceLogin)
