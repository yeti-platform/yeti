import logging
from urllib.parse import urlparse

from core import taskmanager
from core.schemas import observable, task


class DomainExtract(task.InlineTask):
    _defaults = {
        "name": "DomainExtactInline",
        "description": "Extract domain from new URL observable.",
        "acts_on": ["new.observables.url"],
    }

    def run(self, params: dict) -> None:
        if url_id := params.get("id", ""):
            url = observable.Observable.get(url_id)
            logging.info(f"Extracting hostname from: {url.value}")
            o = urlparse(url.value)
            if observable.IPv4.is_valid(o.hostname):
                extracted_obs = observable.IPv4(value=o.hostname).save()
            else:
                extracted_obs = observable.Hostname(value=o.hostname).save()
            url.link_to(extracted_obs, "hostname", "Extracted hostname from URL")
        return


taskmanager.TaskManager.register_task(DomainExtract)
