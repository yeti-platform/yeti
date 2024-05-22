import logging
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import dfiq, task


class DFIQFeed(task.FeedTask):
    _defaults = {
        "name": "DFIQ Github repo",
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
        dfiq.read_from_data_directory(tempdir.name)

        extra_dirs = yeti_config.get("dfiq", "extra_dirs")
        if not extra_dirs:
            return
        for directory in extra_dirs.split(","):
            logging.info("Processing extra directory %s", directory)
            dfiq.read_from_data_directory(directory)


taskmanager.TaskManager.register_task(DFIQFeed)
