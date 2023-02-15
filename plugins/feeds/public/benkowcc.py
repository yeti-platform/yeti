import logging
from datetime import timedelta, datetime

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url, Ip


class BenkowTracker(Feed):
    default_values = {
        "frequency": timedelta(hours=1),
        "name": "BenkowTracker",
        "source": "http://benkow.cc/export.php",
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
                url_obs = Url.get_or_create(value=url)
                url_obs.add_context(context, dedup_list=["date_added"])
                url_obs.add_source(self.name)
                url_obs.tag(tags)

        except ObservableValidationError as e:
            logging.error(e)

        try:
            if ip:
                ip_obs = Ip.get_or_create(value=ip)
                ip_obs.add_context(context, dedup_list=["date_added"])
                ip_obs.add_source(self.name)
                ip_obs.tag(tags)
                if url_obs:
                    ip_obs.active_link_to(url_obs, "url", self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
