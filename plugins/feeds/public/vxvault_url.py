import logging
from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import task
from core.schemas.observables import url


class VXVaultUrl(task.FeedTask):
    # set default values for feed
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "VXVaultUrl",
        "description": "VXVault Community URL list.",
    }

    _SOURCE: ClassVar["str"] = "http://vxvault.net/URL_List.php"

    # should tell yeti how to get and chunk the feed
    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item.strip())

    # don't need to do much here; want to add the information
    # and tag it with 'malware'
    def analyze(self, item):
        if not item:
            return
        tags = ["malware", "dropzone"]
        context = {"source": self.name}
        logging.debug(f"VXVaultUrl: {item}")
        url_obs = url.Url(value=item).save()
        url_obs.add_context(self.name, context)
        url_obs.tag(tags)


taskmanager.TaskManager.register_task(VXVaultUrl)
