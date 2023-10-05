import logging
from datetime import timedelta, datetime

from core.schemas.observables import ipv4, url
from core.schemas import task
from core import taskmanager


class BenkowTracker(task.FeedTask):
    URL_FEED = "https://benkow.cc/export_csv.php"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "BenkowTracker",
        "description": "This feed contains known Malware C2 servers",
    }

    def update(self):
        for index, line in self.update_csv(filter_row="date", delimiter=";", header=0):
            self.analyze(line)

    def analyze(self, line):
        url_obs = False
        url = line["url"]
        ip = line["ip"]
        family = line["type"]
        context = {}
        context["first_seen"] = line["date"]
        context["source"] = self.name
        context["date_added"] = datetime.utcnow()
        tags = []
        tags.append(family.lower())

        url_obs = url.Url(value=url).save()
        url_obs.add_context(self.name, context)
        url_obs.tag(tags)

        ip_obs = ipv4.IPv4(value=ip).save()
        ip_obs.add_context(self.name, context)
        url_obs.link_to(ip_obs, "url-ip", self.name)


taskmanager.TaskManager.register_task(BenkowTracker)
