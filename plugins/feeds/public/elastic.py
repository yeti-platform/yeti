import glob
import json
import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.schemas import indicator, task

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class Elastic(task.FeedTask):
    _defaults = {
        "name": "Elastic",
        "frequency": timedelta(days=1),
        "type": "feed",
        "description": "Collection of protection rules by Elastic Security: https://www.elastic.co/security/endpoint-security",
    }

    _SOURCE_ZIP = (
        "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip"
    )

    def run(self):
        response = self._make_request(self._SOURCE_ZIP, no_cache=True)
        if not response:
            logging.info(f"No response: skipping {self.name} update")
            return

        with tempfile.TemporaryDirectory() as tempdir:
            ZipFile(BytesIO(response.content)).extractall(path=tempdir)

            rules_path = os.path.join(
                tempdir, "protections-artifacts-main", "yara", "rules"
            )
            for file in glob.glob(f"{rules_path}/*.yar"):
                with open(file, "r") as f:
                    rule = f.read()

                indicator.Yara.import_bulk_rules(rule, tags=["Elastic"])


taskmanager.TaskManager.register_task(Elastic)
