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
from core.schemas import entity, indicator, task

ALLOWED_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}


class Neo23x0SignatureBase(task.FeedTask):
    _defaults = {
        "name": "Neo23x0 Signature base",
        "frequency": timedelta(days=1),
        "type": "feed",
        "description": "Gets Yara rules from the Neo23x0/signature-base GitHub repo.",
    }

    def run(self):
        response = self._make_request(
            "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
        )
        if not response:
            logging.info("No response: skipping Neo23x0 Signature base update")
            return

        with tempfile.TemporaryDirectory() as tempdir:
            ZipFile(BytesIO(response.content)).extractall(path=tempdir)
            rules_path = os.path.join(tempdir, "signature-base-master", "yara")

            for file in glob.glob(f"{rules_path}/*.yar"):
                with open(file, "r") as f:
                    rule = f.read()

                try:
                    yara.compile(source=rule, externals=ALLOWED_EXTERNALS)
                except Exception as e:
                    logging.warning(f"Error compiling rule {file}: {e}")
                    raise

                yara_object = indicator.Yara(
                    name=f"Neo23x0: {os.path.basename(file)}",
                    pattern=rule,
                    diamond=indicator.DiamondModel.capability,
                    location="filesystem",
                ).save()

                yara_object.tag(["Neo23x0", "signature-base"])


taskmanager.TaskManager.register_task(Neo23x0SignatureBase)
