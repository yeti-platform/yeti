import glob
import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from artifacts.scripts import validator

from core import taskmanager
from core.schemas import task
from core.schemas.indicators.forensicartifact import ForensicArtifact


class ForensicArtifacts(task.FeedTask):
    _defaults = {
        "name": "ForensicArtifacts GitHub repo",
        "frequency": timedelta(hours=1),
        "type": "feed",
        "description": "Imports ForensicArtifact definitions from the official github repo: https://github.com/forensicartifacts/artifacts",
    }

    def run(self):
        validator_object = validator.ArtifactDefinitionsValidator()

        response = self._make_request(
            "https://github.com/forensicartifacts/artifacts/archive/refs/heads/master.zip"
        )
        if not response:
            logging.info("No response: skipping ForensicArtifact update")
            return

        tempdir = tempfile.TemporaryDirectory()
        ZipFile(BytesIO(response.content)).extractall(path=tempdir.name)
        artifacts_datadir = os.path.join(
            tempdir.name, "artifacts-main", "artifacts", "data"
        )

        data_files_glob = glob.glob(os.path.join(artifacts_datadir, "*.yaml"))
        artifacts_dict = {}
        for file in data_files_glob:
            result = validator_object.CheckFile(file)
            if not result:
                logging.error("Failed to validate %s, skipping", file)
                continue
            logging.info("Processing %s", file)
            with open(file, "r") as f:
                yaml_string = f.read()

            forensic_indicators = ForensicArtifact.from_yaml_string(
                yaml_string, update_parents=False
            )
            for fi in forensic_indicators:
                artifacts_dict[fi.name] = fi

        for artifact in artifacts_dict.values():
            artifact.update_parents(artifacts_dict)
            artifact.save_indicators(create_links=True)


taskmanager.TaskManager.register_task(ForensicArtifacts)
