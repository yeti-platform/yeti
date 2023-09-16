import logging
from datetime import timedelta
from core.schemas.observables import sha256
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
        response = self._make_request(self.SOURCE)
        if response:
            data = response.text
            for item in data.split("\n")[6:-1]:
                self.analyze(item.strip())

    def analyze(self, item):
        val, descr = item.split(" # sha256 - ")

        context = {
            "source": self.name,
            "description": descr,
        }

        obs = sha256.SHA256(value=val).save()
        obs.add_context(self.name, context)
        obs.tag(["botvrij"])


taskmanager.TaskManager.register_task(BotvrijSHA256)
