import json
import logging
from datetime import datetime, timedelta
from io import StringIO

import pandas as pd
from OTXv2 import OTXv2

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import entity, indicator, observable, task


class OTXAlienvault(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "OTXAlienvault",
        "description": "Alienvault OTX",
    }

    _TYPE_MAPPING = {
        "hostname": observable.ObservableType.hostname,
        "domain": observable.ObservableType.hostname,
        "FileHash-MD5": observable.ObservableType.md5,
        "FileHash-SHA256": observable.ObservableType.sha256,
        "FileHash-SHA1": observable.ObservableType.sha1,
        "URL": observable.ObservableType.url,
        "YARA": indicator.IndicatorType.yara,
        "CVE": entity.EntityType.vulnerability,
    }

    def run(self):
        otx_key = yeti_config.get("otx", "key")
        limit = yeti_config.get("otx", "limit")
        days = yeti_config.get("otx", "days")

        assert otx_key, "OTX key not configured in yeti.conf"

        if not limit:
            limit = 50

        if not days:
            last_day = 60

        client_otx = OTXv2(otx_key)
        if not client_otx:
            logging.error("Error to connect to OTX")
            raise Exception("Error to connect to OTX")

        if self.last_run:
            data = client_otx.getsince(timestamp=self.last_run)

        else:
            delta_time = datetime.now() - timedelta(days=last_day)
            logging.debug("Getting OTX data since %s" % delta_time)
            data = client_otx.getsince(timestamp=delta_time)

        df = pd.read_json(
            StringIO(json.dumps(data)), orient="values", convert_dates=["created"]
        )
        df.ffill(inplace=True)

        for _, row in df.iterrows():
            self.analyze(row)

    def analyze(self, item):
        context = dict(source=self.name)
        context["references"] = "\r\n".join(item["references"])
        context["description"] = item["description"]
        context["link"] = "https://otx.alienvault.com/pulse/%s" % item["id"]

        tags = item["tags"]
        for otx_indic in item["indicators"]:
            type_ind = self._TYPE_MAPPING.get(otx_indic["type"])
            if not type_ind:
                continue

            context["title"] = otx_indic["title"]
            context["infos"] = otx_indic["description"]
            context["created"] = datetime.strptime(
                otx_indic["created"], "%Y-%m-%dT%H:%M:%S"
            )
            if type_ind in observable.ObservableType:
                obs = observable.Observable(
                    value=otx_indic["indicator"],
                    type=self._TYPE_MAPPING.get(otx_indic["type"]),
                ).save()

                obs.tag(tags)
                obs.add_context(self.name, context)

            elif type_ind in entity.EntityType:
                entity.Entity(
                    name=otx_indic["indicator"],
                    type=self._TYPE_MAPPING.get(otx_indic["type"]),
                ).save()

            elif type_ind in indicator.IndicatorType:
                if type_ind == indicator.IndicatorType.yara:
                    indicator.Indicator(
                        name=f"YARA_{otx_indic['indicator']}",
                        pattern=otx_indic["content"],
                        type=indicator.IndicatorType.yara,
                        location="OTX",
                        diamond=indicator.DiamondModel.capability,
                    ).save()


taskmanager.TaskManager.register_task(OTXAlienvault)
