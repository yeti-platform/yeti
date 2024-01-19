import json
import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.schemas import dfiq, task

def _process_scenario(obj):
    print(obj)
    # return entity.DFIQScenario(
    #     name=obj["name"],
    #     description=_format_description_from_obj(obj),
    #     dfiq_id=obj["id"],
    #     dfiq_version=obj["x_dfiq_version"],
    #     tags=obj.get("tags", []),
    #     contributors=obj.get("x_dfiq_contributors", []),
    # ).save()

TYPE_FUNCTIONS = {
    "scenarios": _process_scenario,
}


class DFIQFeed(task.FeedTask):
    _defaults = {
        "name": "MitreAttack",
        "frequency": timedelta(hours=1),
        "type": "feed",
        "description": "DFIQ feed",
    }

    def run(self):
        response = self._make_request(
            "https://github.com/google/dfiq/archive/refs/heads/main.zip"
        )
        if not response:
            logging.info("No response: skipping DFIQ update")
            return

        tempdir = tempfile.TemporaryDirectory()
        ZipFile(BytesIO(response.content)).extractall(path=tempdir.name)
        dfiq_datadir = os.path.join(
            tempdir.name, "dfiq-main", "data"
        )

        object_cache = {}

        for subdir in TYPE_FUNCTIONS:
            logging.info("Processing %s", subdir)
            obj_count = 0
            if not os.path.isdir(os.path.join(dfiq_datadir, subdir)):
                continue
            for file in os.listdir(os.path.join(dfiq_datadir, subdir)):
                if not file.endswith(".yaml"):
                    continue
                with open(os.path.join(dfiq_datadir, subdir, file), "r") as f:
                    TYPE_FUNCTIONS[subdir](f.read())
                    obj_count +=1

            logging.info("Processed %s %s objects", obj_count, subdir)

        # logging.info("Processing relationships")
        # rel_count = 0
        # for file in os.listdir(os.path.join(dfiq_datadir, "relationship")):
        #     if not file.endswith(".json"):
        #         continue
        #     with open(os.path.join(dfiq_datadir, "relationship", file), "r") as f:
        #         data = json.load(f)
        #         for item in data["objects"]:
        #             if item.get("revoked"):
        #                 continue
        #             if item['relationship_type'] == 'revoked-by':
        #                 continue

        #             if item["source_ref"].startswith("x-mitre") or item[
        #                 "target_ref"
        #             ].startswith("x-mitre"):
        #                 continue

        #             source = object_cache.get(item["source_ref"])
        #             target = object_cache.get(item["target_ref"])

        #             if not source:
        #                 logging.error("Missing source for %s", item["source_ref"])
        #             if not target:
        #                 logging.error("Missing target for %s", item["target_ref"])

        #             if source and target:
        #                 source.link_to(
        #                     target,
        #                     item["relationship_type"],
        #                     item.get("description", ""),
        #                 )
        #                 rel_count += 1
        # logging.info("Processed %s relationships", rel_count)


taskmanager.TaskManager.register_task(DFIQFeed)
