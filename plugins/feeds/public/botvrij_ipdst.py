from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import task
from core.schemas.observables import ipv4


class BotvrijIPDst(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://www.botvrij.eu/data/ioclist.ip-dst"
    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijIPDst",
        "description": "Botvrij.eu is a project of the Dutch National Cyber Security Centre (NCSC-NL) and SIDN Labs, the R&D team of SIDN, the registry for the .nl domain.",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            for item in data.split("\n")[6:-1]:
                self.analyze(item.strip())

    def analyze(self, item):
        ip, descr = item.split(" # ip-dst - ")

        context = {
            "source": self.name,
            "description": descr,
        }

        obs = ipv4.IPv4(value=ip).save()
        obs.add_context(self.name, context)
        obs.tag(["botvrij"])


taskmanager.TaskManager.register_task(BotvrijIPDst)
