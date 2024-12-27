import glob
import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.schemas import indicator, task


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

                indicator.Yara.import_bulk_rules(
                    rule, tags=["Neo23x0", "signature-base"]
                )


taskmanager.TaskManager.register_task(Neo23x0SignatureBase)
