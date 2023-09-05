import logging
from datetime import timedelta, datetime

from core.schemas import observable
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

        try:
            if url:
                url_obs = observable.Observable.find(value=url)
                if not url_obs:
                    url_obs = observable.Observable(value=url, type="url").save()
                url_obs.add_context(self.name, context)
                url_obs.tag(tags)

        except Exception as e:
            logging.error(e)

        try:
            if ip:
                ip_obs = observable.Observable.find(value=ip)
                if not ip_obs:
                    ip_obs = observable.Observable(value=ip, type="ip").save()
                ip_obs.add_context(self.name, context)
                if url_obs:
                    url_obs.link_to(ip_obs, "url-ip", self.name)
        except Exception as e:
            logging.error(e)
