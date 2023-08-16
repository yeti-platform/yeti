import logging
from datetime import timedelta, datetime
from core.schemas import observable
from core.schemas import task
from core import taskmanager



class BlocklistdeAll(task.FeedTask):
    URL_FEED = "https://lists.blocklist.de/lists/all.txt"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BlocklistdeAll",
        "description": "All IP addresses that have attacked one of our customers/servers in the last 48 hours. It's not recommended to use this feed due to the lesser amount of contextual information, it's better to use each blocklist.de feed separately.",
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
            obs.tag(["blocklist"])

        except Exception as e:
            logging.error(e)
taskmanager.TaskManager.register_task(BlocklistdeAll)