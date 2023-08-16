import logging
from datetime import timedelta, datetime
from core.schemas import observable
from core.schemas import task
from core import taskmanager


class BotvrijSHA256(task.FeedTask):
    SOURCE = "https://www.botvrij.eu/data/ioclist.sha256"

    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijSHA256",
        "description": "Botvrij.eu is a project of the Dutch National Cyber Security Centre (NCSC-NL) and SIDN Labs, the R&D team of SIDN, the registry for the .nl domain.",
    }

    def run(self):
        response = self._make_request(self.SOURCE, verify=True)
        if response:
            data = response.text
            for item in data.split("\n")[6:-1]:
                self.analyze(item.strip())

    def analyze(self, item):
        val, descr = item.split(" # sha256 - ")

        context = {
            "source": self.name,
            "description": descr,
            "date_added": datetime.utcnow(),
        }

        obs = observable.Observable.find(value=val)
        if not obs:
            obs = observable.Observable(value=val, type="sha256").save()
        obs.add_context(self.name, context)
        obs.tag(["botvrij"])

taskmanager.TaskManager.register_task(BotvrijSHA256)
