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

ALLOWED_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}


class YaraForge(task.FeedTask):
    _defaults = {
        "name": "YaraForge",
        "frequency": timedelta(days=1),
        "type": "feed",
        "description": "Collection of community Yara rules: https://yarahq.github.io/",
    }

    _SOURCE_ZIP = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"

    def run(self):
        response = self._make_request(self._SOURCE_ZIP, no_cache=True)
        if not response:
            logging.info(f"No response: skipping {self.name} update")
            return

        with tempfile.TemporaryDirectory() as tempdir:
            ZipFile(BytesIO(response.content)).extractall(path=tempdir)

            rules_path = os.path.join(
                tempdir, "packages", "core", "yara-rules-core.yar"
            )
            with open(rules_path, "r") as f:
                rules = f.read()

            indicator.Yara.import_bulk_rules(rules, tags=["yara-forge-core"])


taskmanager.TaskManager.register_task(YaraForge)
