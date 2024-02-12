import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import dfiq, indicator, task


def extract_indicators(approach) -> None:
    for processor in approach.view.processors:
        for analysis in processor.analysis:
            for step in analysis.steps:
                if step.type == 'manual':
                    continue

                query = indicator.Query.find(pattern=step.value)
                if not query:
                    query = indicator.Query(
                        name=step.description,
                        pattern=step.value,
                        relevant_tags=approach.dfiq_tags or [],
                        query_type=step.type,
                        location=step.type,
                        diamond=indicator.DiamondModel.victim,
                    ).save()
                approach.link_to(query, "query", "Uses query")


    for data in approach.view.data:
        if data.type == "ForensicArtifact":
            artifact = indicator.ForensicArtifact.find(name=data.value)
            if not artifact:
                logging.warning(
                    "Missing artifact %s in %s", data.value, approach.dfiq_id
                )
                continue
            approach.link_to(artifact, "artifact", "Uses artifact")
        else:
            logging.warning("Unknown data type %s in %s", data.type, approach.dfiq_id)


class DFIQFeed(task.FeedTask):
    _defaults = {
        "name": "DFIQ Github repo",
        "frequency": timedelta(hours=1),
        "type": "feed",
        "description": "DFIQ feed",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dfiq_kb = {}

    def read_from_data_directory(self, directory: str) -> None:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".yaml"):
                    if 'spec' in file or 'template' in file:
                    # Don't process DIFQ specification files
                        continue
                    with open(os.path.join(root, file), "r") as f:
                        try:
                            dfiq_object = dfiq.DFIQBase.from_yaml(f.read()).save()
                        except ValueError as e:
                            logging.error("Error processing %s: %s", file, e)
                            continue
                    self._dfiq_kb[dfiq_object.dfiq_id] = dfiq_object

        for dfiq_id, dfiq_object in self._dfiq_kb.items():
            dfiq_object.update_parents()
            if dfiq_object.type == dfiq.DFIQType.approach:
                extract_indicators(dfiq_object)

    def run(self):
        response = self._make_request(
            "https://github.com/google/dfiq/archive/refs/heads/main.zip"
        )
        if not response:
            logging.info("No response: skipping DFIQ update")
            return

        tempdir = tempfile.TemporaryDirectory()
        ZipFile(BytesIO(response.content)).extractall(path=tempdir.name)
        self.read_from_data_directory(tempdir.name)

        extra_dirs = yeti_config.get("dfiq", "extra_dirs")
        if not extra_dirs:
            return
        for directory in extra_dirs.split(","):
            print(f"Processing extra directory {directory}")
            self.read_from_data_directory(directory)


taskmanager.TaskManager.register_task(DFIQFeed)
