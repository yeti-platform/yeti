from io import StringIO
import json
import logging
from datetime import timedelta, datetime

import pandas as pd

from core.schemas import observable
from core.schemas import task
from core import taskmanager


class HybridAnalysis(task.FeedTask):
    SOURCE = "https://www.hybrid-analysis.com/feed?json"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "HybridAnalysis",
        "description": "Hybrid Analysis is a free malware analysis service powered by Payload Security that detects and analyzes unknown threats using a unique Hybrid Analysis technology.",
    }

    def run(self):
        headers = {"User-agent": "VxApi Connector"}
        response = self._make_request(self.SOURCE, verify=True, headers=headers)
        if response:
            data = response.json()
            if "data" in data:
                df = pd.read_json(
                    StringIO(json.dumps(data["data"])),
                    orient="values",
                    convert_dates=["analysis_start_time"],
                )
                df.fillna("", inplace=True)
                df = self._filter_observables_by_time(df, "analysis_start_time")
                for _, row in df.iterrows():
                    self.analyze(row)

    # pylint: disable=arguments-differ
    def analyze(self, item):
        first_seen = item["analysis_start_time"]

        f_hyb = observable.Observable.find(value=f"FILE:{item['sha256']}")
        if not f_hyb:
            f_hyb = observable.Observable(
                value=f"FILE:{item['sha256']}", type="file"
            ).save()

        sha256 = observable.Observable.find(value=item["sha256"])
        if not sha256:
            sha256 = observable.Observable(value=item["sha256"], type="sha256").save()

        f_hyb.link_to(sha256, "sha256", self.name)
        tags = []
        context = {
            "source": self.name,
            "date": first_seen,
        }

        if "vxfamily" in item:
            context["vxfamily"] = item["vxfamily"]

        if "tags" in item:
            tags.extend(item["tags"])

        if "threatlevel_human" in item:
            context["threatlevel_human"] = item["threatlevel_human"]

        if "threatlevel" in item:
            context["threatlevel"] = item["threatlevel"]

        if "type" in item:
            context["type"] = item["type"]

        if "size" in item:
            context["size"] = item["size"]

        if "vt_detect" in item:
            context["virustotal_score"] = item["vt_detect"]

        if "et_alerts_total" in item:
            context["et_alerts_total"] = item["et_alerts_total"]

        if "process_list" in item:
            context["count_process_spawn"] = len(item["process_list"])

        context["url"] = "https://www.hybrid-analysis.com" + item["reporturl"]

        f_hyb.add_context(self.name, context)
        f_hyb.tag(tags)

        sha256.add_context(self.name, context)
        sha256.tag(tags)

        md5 = observable.Observable.find(value=item["md5"])
        if not md5:
            md5 = observable.Observable(value=item["md5"], type="md5").save()

        md5.add_context(self.name, context)
        md5.tag(tags)
        f_hyb.link_to(md5, "md5", self.name)

        sha1 = observable.Observable.find(value=item["sha1"])
        if not sha1:
            sha1 = observable.Observable(value=item["sha1"], type="sha1").save()

        sha1.add_context(self.name, context)
        sha1.tag(tags)
        f_hyb.link_to(sha1, "sha1", self.name)

        if "domains" in item:
            for domain in item["domains"]:
                new_host = observable.Observable.find(value=domain)
                if not new_host:
                    new_host = observable.Observable(
                        value=domain, type="hostname"
                    ).save()

                f_hyb.link_to(new_host, "contacted", self.name)
                logging.debug(domain)
                new_host.add_context(
                    self.name, {"source": self.name, "contacted_by": f_hyb}
                )
                new_host.tag(tags)

        if "extracted_files" in item:
            for extracted_file in item["extracted_files"]:
                context_file_dropped = {"source": self.name}

                if not "sha256" in extracted_file:
                    logging.error(extracted_file)
                    continue

                new_file = observable.Observable.find(
                    value=f"FILE:{extracted_file['sha256']}"
                )
                if not new_file:
                    new_file = observable.Observable(
                        value=f"FILE:{extracted_file['sha256']}", type="file"
                    ).save()
                sha256_new_file = observable.Observable.find(
                    value=extracted_file["sha256"]
                )
                if not sha256_new_file:
                    sha256_new_file = observable.Observable(
                        value=extracted_file["sha256"], type="sha256"
                    ).save()

                new_file.link_to(sha256_new_file, "sha256", self.name)

                context_file_dropped["virustotal_score"] = 0
                context_file_dropped["size"] = extracted_file["file_size"]

                if "av_matched" in extracted_file:
                    context_file_dropped["virustotal_score"] = extracted_file[
                        "av_matched"
                    ]

                if "threatlevel_readable" in extracted_file:
                    context_file_dropped["threatlevel"] = extracted_file[
                        "threatlevel_readable"
                    ]

                if "av_label" in extracted_file:
                    context_file_dropped["av_label"] = extracted_file["av_label"]

                if "type_tags" in extracted_file:
                    new_file.tag(extracted_file["type_tags"])

                new_file.add_context(self.name, context_file_dropped)
                sha256_new_file.add_context(self.name, context_file_dropped)

                f_hyb.link_to(new_file, "dropped", self.name)


taskmanager.TaskManager.register_task(HybridAnalysis)
