import logging
from datetime import timedelta
from core.schemas.observables import ipv4
from core.schemas import task
from core import taskmanager


class Cruzit(task.FeedTask):
    SOURCE = "https://iplists.firehol.org/files/cruzit_web_attacks.ipset"

    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "Cruzit",
        "description": "IP addresses that have been reported within the last 48 hours for attacks on the Service FTP, IMAP, Apache, Apache-DDOS, RFI-Attacks, and Web-Logins with Brute-Force Logins.",
    }

    def run(self):
        response = self._make_request(self.SOURCE)
        if response:
            data = response.text
            for line in data.split("\n")[63:]:
                self.analyze(line)

    def analyze(self, line):
        ip_str = line.strip()

        obs = ipv4.IPv4.find(value=ip_str)
        if not obs:
            obs = ipv4.IPv4(value=ip_str).save()
        obs.tag(["cruzit", "web attacks"])


taskmanager.TaskManager.register_task(Cruzit)
