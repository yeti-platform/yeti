import logging
from urllib.parse import urlparse

from core import taskmanager
from core.schemas import observable, task


class DomainExtract(task.InlineTask):
    _defaults = {
        "name": "DomainExtactInline",
        "description": "Extract domain from new URL observable.",
    }

    def run(self, params: dict) -> None:
        event = params.get("event", "")
        if event.startswith("new.observables.url"):
            _, id = event.split(":", 1)
            url = observable.Observable.get(id)
            logging.info(f"Extracting hostname from: {url.value}")
            o = urlparse(url.value)
            hostname = observable.Hostname(value=o.hostname).save()
            url.link_to(hostname, "hostname", "Extracted hostname from URL")
        return
    
taskmanager.TaskManager.register_task(DomainExtract)
