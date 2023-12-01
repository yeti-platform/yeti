import logging
import re
from datetime import timedelta, datetime

from core.config.config import yeti_config

# Variable
VTAPI = yeti_config.get("vt", "key")
headers = {"x-apikey": VTAPI}
limit = 10
params = {"limit": limit}
regex = "[A-Fa-f0-9]{64}"  # Find SHA256


class VirusTotalPriv(Feed):
    _defaults = {
        "frequency": timedelta(minutes=5),
        "name": "VirusTotalHuntingV3",
        "source": "https://www.virustotal.com/api/v3/intelligence/hunting_notifications",
        "description": "Feed of hunting for VirusTotal API v3",
    }

    settings = {
        "vt_url_hunting_v3": {
            "name": "VT Url Hunting v3",
            "description": "Hunting feed for VT API v3",
        }
    }

    def update(self):
        if VTAPI:
            self.source = (
                "https://www.virustotal.com/api/v3/intelligence/hunting_notifications"
            )
            for index, item in self.update_json(
                params=params, headers=headers, key="data"
            ):
                self.analyze(item)
        else:
            logging.error("Your VT API key is not set in the config file!")

    def analyze(self, item):
        tags = []

        context = {"source": self.name, "date_added": datetime.utcnow()}

        # Parse value of interest
        subject = item["attributes"]["rule_name"]
        date = item["attributes"]["date"]
        tags2 = item["attributes"]["tags"]
        sha2 = re.search(regex, str(tags2)).group()
        date_string = datetime.utcfromtimestamp(date).strftime("%d/%m/%Y %H:%M:%S")
        tags2.remove(sha2)

        # Update to Yeti DB
        f_vt3 = File.get_or_create(value="FILE:{}".format(sha2))
        sha256 = Hash.get_or_create(value=sha2)
        f_vt3.active_link_to(sha256, "sha256", self.name)
        tags.append(tags2)
        tags.append(subject)
        context["date_added"] = date_string
        context["snippet"] = item["attributes"]["snippet"]
        # context['source_country'] = item["attributes"]['source_country']

        context["raw"] = item
        context["date_added"] = datetime.utcnow()

        f_vt3.tag(str(tags))
        f_vt3.add_context(context, dedup_list=["date_added"])
