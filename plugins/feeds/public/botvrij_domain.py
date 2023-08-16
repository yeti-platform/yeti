import logging
from datetime import timedelta, datetime
from core.schemas import observable
from core.schemas import task
from core import taskmanager


class BotvrijDomain(task.FeedTask):
    URL_FEED = "https://www.botvrij.eu/data/ioclist.domain"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijDomain",
        "description": "Botvrij.eu is a project of the Dutch National Cyber Security Centre (NCSC-NL) and SIDN Labs, the R&D team of SIDN, the registry for the .nl domain.",
    }

    def run(self):
        response = self._make_request(self.URL_FEED, verify=True)
        if response:
            data = response.text
            for item in data.split("\n")[6:-1]:
                self.analyze(item.strip())

    def analyze(self, item):
        hostn, descr = item.split(" # domain - ")

        context = {
            "source": self.name,
            "description": descr,
            "date_added": datetime.utcnow(),
        }

        obs = observable.Observable.find(value=hostn)
        if not obs:
            obs = observable.Observable(value=hostn, type="hostname").save()
        obs.add_context(self.name, context)
        obs.tag(["botvrij"])


taskmanager.TaskManager.register_task(BotvrijDomain)
