from urllib.parse import urlparse

from core import taskmanager
from core.events.message import Message
from core.schemas import observable, task


class HostnameExtract(task.EventTask):
    _defaults = {
        "name": "HostnameExtact",
        "description": "Extract hostname (domain or ip) from new URL observable.",
        "acts_on": "(new|update):observable:url",
    }

    def run(self, message: Message) -> None:
        url = message.data.yeti_object
        self.logger.info(f"Extracting hostname from: {url.value}")
        o = urlparse(url.value)
        if observable.IPv4.is_valid(o.hostname):
            extracted_obs = observable.IPv4(value=o.hostname)
        else:
            extracted_obs = observable.Hostname(value=o.hostname)
        url.link_to(extracted_obs.save(), "hostname", "Extracted hostname from URL")
        return


taskmanager.TaskManager.register_task(HostnameExtract)
