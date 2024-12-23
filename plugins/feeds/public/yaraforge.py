import glob
import json
import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

import yara

from core import taskmanager
from core.schemas import indicator, task

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
        response = self._make_request(self._SOURCE_ZIP)
        if not response:
            logging.info(f"No response: skipping {self.name} update")
            return

        with tempfile.TemporaryDirectory() as tempdir:
            ZipFile(BytesIO(response.content)).extractall(path=tempdir)
            rules_path = os.path.join(tempdir, "packages", "core")

            for file in glob.glob(f"{rules_path}/*.yar"):
                with open(file, "r") as f:
                    rule = f.read()

                try:
                    yara.compile(source=rule, externals=ALLOWED_EXTERNALS)
                except Exception as e:
                    logging.warning(f"Error compiling rule {file}: {e}")
                    raise

                yara_object = indicator.Yara(
                    name="Yara forge: core",
                    pattern=rule,
                    diamond=indicator.DiamondModel.capability,
                    location="filesystem",
                ).save()

                yara_object.tag(["yara-forge", "core"])


taskmanager.TaskManager.register_task(YaraForge)
