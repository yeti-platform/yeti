import logging
from datetime import timedelta
from typing import ClassVar
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class TorExitNodes(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "TorExitNodes",
        "description": "Tor exit nodes",
    }
    _SOURCE:ClassVar['str'] = "https://www.dan.me.uk/tornodes"

    def run(self):
        feed = self._make_request(self._SOURCE).text

        start = feed.find("<!-- __BEGIN_TOR_NODE_LIST__ //-->") + len(
            "<!-- __BEGIN_TOR_NODE_LIST__ //-->"
        )
        end = feed.find("<!-- __END_TOR_NODE_LIST__ //-->")
        logging.debug(f"start: {start}, end: {end}")

        feed_raw = (
            feed[start:end]
            .replace("\n", "")
            .replace("<br />", "\n")
            .replace("&gt;", ">")
            .replace("&lt;", "<")
        )

        feed = feed_raw.split("\n")
        if len(feed) > 10:
            self.status = "OK"

        for line in feed:
            self.analyze(line)

        return True

    def analyze(self, line):
        fields = line.split("|")

        if len(fields) < 8:
            return

        context = {
            "name": fields[1],
            "router-port": fields[2],
            "directory-port": fields[3],
            "flags": fields[4],
            "version": fields[6],
            "contactinfo": fields[7],
            "source": self.name,
            "description": f"Tor exit node: {fields[1]} {fields[0]}",
        }

        ip_obs = ipv4.IPv4(value=fields[0]).save()
        ip_obs.add_context(self.name, context)
        ip_obs.tag(["tor", "exitnode"])


taskmanager.TaskManager.register_task(TorExitNodes)
