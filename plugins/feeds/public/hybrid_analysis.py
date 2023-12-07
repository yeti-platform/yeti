from io import StringIO
import json
import logging
from datetime import timedelta
from typing import ClassVar

import pandas as pd

from core.schemas.observables import file, sha256, sha1, md5, hostname,path
from core.schemas import task
from core import taskmanager


class HybridAnalysis(task.FeedTask):
    _SOURCE: ClassVar["str"] = "https://www.hybrid-analysis.com/feed?json"
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "HybridAnalysis",
        "description": "Hybrid Analysis is a free malware analysis service powered by Payload Security that detects and analyzes unknown threats using a unique Hybrid Analysis technology.",
    }

    def run(self):
        headers = {"User-agent": "VxApi Connector"}
        response = self._make_request(self._SOURCE, headers=headers)
        if response:
            data = response.json()
            if "data" in data:
                df = pd.read_json(
                    StringIO(json.dumps(data["data"])),
                    orient="values",
                    convert_dates=["analysis_start_time"],
                )
                df.fillna(0, inplace=True)
                df = self._filter_observables_by_time(df, "analysis_start_time")
                for _, row in df.iterrows():
                    self.analyze(row)

    def analyze(self, item):
        logging.debug(f"HybridAnalysis: {item}")
        first_seen = item["analysis_start_time"]

        f_hyb = file.File(value=f"FILE:{item['sha256']}").save()
        sha256_obs = sha256.SHA256(value=item["sha256"]).save()

        f_hyb.link_to(sha256_obs, "sha256", self.name)
        tags = []
        context = {
            "source": self.name,
            "date": first_seen,
        }

        if "vxfamily" in item:
            context["vxfamily"] = item["vxfamily"]

        if "tags" in item and isinstance(item["tags"], list):
            tags.extend(item["tags"])

        if "threatlevel_human" in item:
            context["threatlevel_human"] = item["threatlevel_human"]

        if "threatlevel" in item:
            context["threatlevel"] = item["threatlevel"]

        if "type" in item:
            context["type"] = item["type"]

        if "size" in item:
            context["size"] = item["size"]
            if item["size"]:
                f_hyb.size = int(item["size"])

        if "vt_detect" in item:
            context["virustotal_score"] = item["vt_detect"]

        if "et_alerts_total" in item:
            context["et_alerts_total"] = item["et_alerts_total"]

        if "process_list" in item:
            context["count_process_spawn"] = len(item["process_list"])

        context["url"] = "https://www.hybrid-analysis.com" + item["reporturl"]

        logging.debug(f"HybridAnalysis: {context}")

        f_hyb.add_context(self.name, context)
        f_hyb.tag(tags)

        sha256_obs.add_context(self.name, context)
        sha256_obs.tag(tags)

        md5_obs = md5.MD5(value=item["md5"]).save()
        md5_obs.add_context(self.name, context)
        md5_obs.tag(tags)
        f_hyb.link_to(md5_obs, "md5", self.name)

        sha1_obs = sha1.SHA1(value=item["sha1"]).save()
        sha1_obs.add_context(self.name, context)
        sha1_obs.tag(tags)
        f_hyb.link_to(sha1_obs, "sha1", self.name)

        if "domains" in item and isinstance(item["domains"], list):
            for domain in item["domains"]:
                new_host = hostname.Hostname(value=domain).save()
                f_hyb.link_to(new_host, "contact", self.name)
                new_host.tag(tags)

        if "extracted_files" in item and isinstance(item["extracted_files"], list):
            for extracted_file in item["extracted_files"]:
                context_file_dropped = {"source": self.name}

                if not "sha256" in extracted_file:
                    logging.error(extracted_file)
                    continue

                new_file = file.File(
                    value=f"FILE:{extracted_file['sha256']}", type="file"
                ).save()
                sha256_new_file = sha256.SHA256(value=extracted_file["sha256"]).save()

                new_file.link_to(sha256_new_file, "sha256", self.name)
                
                path_extracted_file = None
                if extracted_file["file_path"] and isinstance(extracted_file["file_path"], str):
                    path_extracted_file = path.Path(value=extracted_file["file_path"]).save()
                    new_file.link_to(path_extracted_file, "path", self.name)

                context_file_dropped["virustotal_score"] = 0
                context_file_dropped["size"] = extracted_file["file_size"]

                if "av_matched" in extracted_file and isinstance('av_matched', int):
                    context_file_dropped["virustotal_score"] = extracted_file[
                        "av_matched"
                    ]

                if "threatlevel_readable" in extracted_file and isinstance('threatlevel_readable', str):
                    context_file_dropped["threatlevel"] = extracted_file[
                        "threatlevel_readable"
                    ]

                if "av_label" in extracted_file and isinstance('av_label', str):
                    context_file_dropped["av_label"] = extracted_file["av_label"]

                if "type_tags" in extracted_file and isinstance('type_tags', list):
                    new_file.tag(extracted_file["type_tags"])
                    if path_extracted_file:
                        path_extracted_file.tag(extracted_file["type_tags"])
                    
                    sha256_new_file.tag(extracted_file["type_tags"])

                new_file.add_context(self.name, context_file_dropped)
                sha256_new_file.add_context(self.name, context_file_dropped)
                f_hyb.link_to(new_file, "dropped", self.name)


taskmanager.TaskManager.register_task(HybridAnalysis)
