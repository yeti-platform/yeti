import logging
from datetime import timedelta, datetime
from core.schemas.observables import hostname
from core.schemas import task
from core import taskmanager


class BotvrijHostname(task.FeedTask):
    SOURCE = "https://www.botvrij.eu/data/ioclist.hostname"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijHostname",
        "description": "Botvrij.eu is a project of the Dutch National Cyber Security Centre (NCSC-NL) and SIDN Labs, the R&D team of SIDN, the registry for the .nl domain.",
    }

    def run(self):
        response = self._make_request(self.SOURCE)
        if response:
            data = response.text
            for item in data.split("\n")[6:-1]:
                self.analyze(item.strip())

    def analyze(self, item):
        hostn, descr = item.split(" # hostname - ")

        context = {
            "source": self.name,
            "description": descr,
        }

        obs = hostname.Hostname(value=hostn).save()
        obs.add_context(self.name, context)
        obs.tag(["botvrij"])


taskmanager.TaskManager.register_task(BotvrijHostname)
