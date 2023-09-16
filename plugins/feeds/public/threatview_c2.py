import logging
import re
from datetime import datetime, timedelta
from core.schemas import observable
from core.schemas import task
from core import taskmanager



class ThreatviewC2(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "ThreatviewC2",
        "description": "This feed contains Cobalt Strike C2 IPs and Hostnames",
    }

    SOURCE = "https://threatview.io/Downloads/High-Confidence-CobaltstrikeC2_IP_feed.txt"
    def run(self):
        response = self._make_request(self.SOURCE,sort=False)
        if response:
            lines = response.content.decode("utf-8").split("\n")[2:-1]
            for line in lines:
                self.analyze(line)

    def analyze(self, item):
        item = item.strip()

        context = {"source": self.name}
        tags = ["c2", "cobaltstrike"]

        try:
            obs = observable.Observable.add_text(item)
            obs.add_context(self.name, context)
            obs.tag(tags)
        except ValueError as error:
            return logging.error(error)


taskmanager.TaskManager.register_task(ThreatviewC2)
