import logging
from datetime import timedelta, datetime
from typing import ClassVar
from core.schemas.observables import url
from core.schemas import task
from core import taskmanager


class BotvrijUrl(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://www.botvrij.eu/data/ioclist.url"

    _defaults = {
        "frequency": timedelta(hours=12),
        "name": "BotvrijUrl",
        "description": "Botvrij.eu is a project of the Dutch National Cyber Security Centre (NCSC-NL) and SIDN Labs, the R&D team of SIDN, the registry for the .nl domain.",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            for item in data.split("\n")[6:-1]:
                self.analyze(item.strip())

    def analyze(self, item):
        url_str, descr = item.split(" # url - ")

        context = {
            "source": self.name,
            "description": descr,
        }

        obs = url.Url(value=url_str).save()
        obs.add_context(self.name, context)
        obs.tag(["botvrij"])


taskmanager.TaskManager.register_task(BotvrijUrl)
