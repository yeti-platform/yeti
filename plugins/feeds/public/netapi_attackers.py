import csv
import logging
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import ClassVar

from core import taskmanager
from core.schemas import observable, task

# Attack categories of the feed: A malware (infection attempts and the servers they
# download from), B password guessing, C exploits, D form spam.
CATEGORIES = {"A": "malware", "B": "bruteforce", "C": "exploit", "D": "spam"}


class NetAPIAttackers(task.FeedTask):
    _SOURCE: ClassVar["str"] = (
        "https://netapi.com/api2/?method=compromised&dataset_type=ip&format=csv"
    )
    # A hit reaches the CSV up to about 75 minutes after it happened (the sensor data
    # is imported hourly, the file is rebuilt hourly after that), while last_run is
    # set when a run ends. Rows seen shortly before the last run are therefore
    # imported again, so that late arrivals are not skipped.
    _LOOKBACK: ClassVar[timedelta] = timedelta(hours=3)
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "NetAPIAttackers",
        "description": "IPv4 addresses that attacked the NetAPI honeypot sensors in the last 48 hours, "
        "with the attack types (hourly, CC BY 4.0, no API key needed)",
    }

    def run(self):
        response = self._make_request(self._SOURCE)
        if not response:
            return
        since = self.last_run - self._LOOKBACK if self.last_run else None
        for row in csv.DictReader(StringIO(response.text)):
            if since and not self._seen_since(row, since):
                continue
            self.analyze(row)

    @staticmethod
    def _seen_since(row, since):
        """True when the row's last_seen (ISO 8601 UTC) is after since, or unparsable."""
        try:
            last_seen = datetime.fromisoformat((row.get("last_seen") or "").strip())
        except ValueError:
            return True
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        return last_seen > since

    def analyze(self, row):
        ip_str = (row.get("ip") or "").strip()
        if not ip_str:
            return

        context = {
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

        try:
            obs = observable.save(type="ipv4", value=ip_str, tags=tags)
        except ValueError:
            logging.warning(f"{self.name}: skipping invalid IPv4 value {ip_str!r}")
            return
        # One context entry per address: replace it when last_seen, sensors or threats change.
        obs.add_context(self.name, context, overwrite=True)


taskmanager.TaskManager.register_task(NetAPIAttackers)
