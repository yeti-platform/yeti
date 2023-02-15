from mongoengine import DictField
from datetime import timedelta

import dateutil.parser
from OTXv2 import OTXv2

from core.feed import Feed
from core.observables import Ip, Url, Hostname, Hash, Email
from core.config.config import yeti_config

OBSERVABLE_TYPES = {
    "IPv4": Ip,
    "domain": Hostname,
    "hostname": Hostname,
    "email": Email,
    "URL": Url,
    "FileHash-MD5": Hash,
    "FileHash-SHA256": Hash,
    "FileHash-SHA1": Hash,
}

# Some observable types are not yet supported by Yeti:
# IPv6
# URI
# FileHash-PEHASH
# FileHash-IMPHASH
# CIDR
# FilePath
# Mutex
# CVE


class OtxFeed(Feed):
    last_runs = DictField()

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "OtxFeed",
        "description": "Parses events from a given OTX pulse",
        "source": "OTX",
    }

    def __init__(self, *args, **kwargs):
        super(OtxFeed, self).__init__(*args, **kwargs)
        self.otx = OTXv2(yeti_config.get("otx", "key"))
        self.get_pulses()

    def get_pulses(self):
        self.pulses = {}

        for pulse in yeti_config.get("otx", "pulses", "").split(","):
            config = {
                "pulse_id": yeti_config.get(pulse, "pulse_id"),
                "use_otx_tags": yeti_config.get(pulse, "use_otx_tags") == "Y" or False,
            }

            if config["pulse_id"]:
                self.pulses[pulse] = config

    def update(self):
        for pulse in self.pulses.values():
            pulse_details = self.otx.get_pulse_details(pulse["pulse_id"])

            pulse_context = {
                "source": "OTX Pulse - {}".format(pulse_details["name"]),
                "pulse_id": pulse["pulse_id"],
                "name": pulse_details["name"],
                "pulse_description": pulse_details["description"],
                "tags": pulse_details["tags"],
                "author_name": pulse_details["author_name"],
                "references": pulse_details["references"],
                "industries": pulse_details["industries"],
                "tlp": pulse_details["TLP"],
                "targeted_countries": pulse_details["targeted_countries"],
                "adversary": pulse_details["adversary"],
                "public": pulse_details["public"],
                "created": dateutil.parser.parse(pulse_details["created"]),
            }

            for indicator in pulse_details["indicators"]:
                self.analyze(
                    indicator, pulse_context, use_otx_tags=pulse["use_otx_tags"]
                )

    def analyze(self, indicator_context, pulse_context, use_otx_tags=False):
        context = pulse_context.copy()
        value = indicator_context.pop("indicator")
        context["date_dadded"] = dateutil.parser.parse(indicator_context.pop("created"))
        context.update(indicator_context)

        observable = OBSERVABLE_TYPES[indicator_context["type"]].get_or_create(
            value=value
        )
        observable.add_context(context)
        if use_otx_tags:
            observable.tag(pulse_context["tags"])
