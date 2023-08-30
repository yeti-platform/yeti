import logging
from datetime import timedelta, datetime
from core.schemas import observable
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
        line = line.strip()

        ip = line

        obs = observable.Observable.find(value=ip)
        if not obs:
            obs = observable.Observable(value=ip, type="ip").save()

        obs.tag(["cruzit", "web attacks"])


taskmanager.TaskManager.register_task(Cruzit)
