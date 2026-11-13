import csv
from datetime import timedelta
from io import StringIO
from typing import ClassVar

from core import taskmanager
from core.schemas import task
from core.schemas.observables import ipv4

# Attack categories of the feed: A malware (infection attempts and the servers they
# download from), B password guessing, C exploits, D form spam.
CATEGORIES = {"A": "malware", "B": "bruteforce", "C": "exploit", "D": "spam"}


class NetAPIAttackers(task.FeedTask):
    _SOURCE: ClassVar["str"] = (
        "https://netapi.com/api2/?method=compromised&dataset_type=ip&format=csv"
    )
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "NetAPIAttackers",
        "source": "https://netapi.com/compromised-ips/",
        "description": "IPv4 addresses that attacked the NetAPI honeypot sensors in the last 48 hours, "
        "with the attack types (hourly, CC BY 4.0, no API key needed)",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if not response:
            return
        for row in csv.DictReader(StringIO(response.text)):
            self.analyze(row)

    def analyze(self, row):
        ip_str = (row.get("ip") or "").strip()
        if not ip_str:
            return

        context = {
            "source": self.name,
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "category": row.get("category"),
            "top_threat": row.get("top_threat"),
            "threats": row.get("threats"),
            "sensors": row.get("sensors"),
        }

        tags = ["netapi", "honeypot"]
        category = CATEGORIES.get((row.get("category") or "").strip())
        if category:
            tags.append(category)
        top_threat = (row.get("top_threat") or "").strip()
        if top_threat:
            tags.append(top_threat)

        obs = ipv4.IPv4(value=ip_str).save()
        obs.add_context(self.name, context)
        obs.tag(tags)


taskmanager.TaskManager.register_task(NetAPIAttackers)
