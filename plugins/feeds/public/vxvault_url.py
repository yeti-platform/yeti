from datetime import timedelta, datetime
import logging

from core.schemas import observable
from core.schemas import task
from core import taskmanager



class VXVaultUrl(task.FeedTask):
    # set default values for feed
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "VXVaultUrl",
        "description": "VXVault Community URL list.",
    }

    SOURCE = "http://vxvault.net/URL_List.php"
    # should tell yeti how to get and chunk the feed
    def run(self):
        response = self._make_request(self.SOURCE, verify=True)
        if response:
            data = response.text
            for item in data.split("\n"):
                self.analyze(item.strip())

    # don't need to do much here; want to add the information
    # and tag it with 'malware'
    def analyze(self, item):
        
        tags = ["malware", "dropzone"]
        context = {"source": self.name}
        
        url_obs = observable.Observable.find(value=item)
        if not url_obs:
            url_obs = observable.Observable(value=item, type="url").save()
        url_obs.add_context(self.name, context)
        url_obs.tag(tags)

taskmanager.TaskManager.register_task(VXVaultUrl)