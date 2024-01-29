from datetime import timedelta
from typing import ClassVar
from core.schemas.observables import file
from core.schemas import task
from core import taskmanager


class BotvrijFilename(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://www.botvrij.eu/data/ioclist.filename"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijFilename",
        "description": "Botvrij.eu is a project of the Dutch National Cyber Security Centre (NCSC-NL) and SIDN Labs, the R&D team of SIDN, the registry for the .nl domain.",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            for item in data.split("\n")[6:-1]:
                self.analyze(item.strip())

    def analyze(self, item):
        filen, descr = item.split(" # filename - ")

        context = {
            "source": self.name,
            "description": descr,
        }

        obs = file.File(value=filen).save()
        obs.name = filen
        obs.add_context(self.name, context)
        obs.tag(["botvrij"])


taskmanager.TaskManager.register_task(BotvrijFilename)
