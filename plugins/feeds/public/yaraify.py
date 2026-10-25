import logging
from datetime import timedelta
from io import BytesIO
from typing import ClassVar
from zipfile import ZipFile

import plyara.exceptions

from core import errors, taskmanager
from core.schemas import indicator, task


class YARAify(task.FeedTask):
    _defaults = {
        "frequency": timedelta(days=1),
        "name": "YARAify",
        "description": "This feed contains yara rules",
        "source": "",
    }

    _SOURCE_ALL_RULES: ClassVar["str"] = (
        "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"
    )

    def run(self):
        response = self._make_request(self._SOURCE_ALL_RULES)
        if not response:
            return
        imported = failed = 0
        with ZipFile(BytesIO(response.content)) as zfile:
            for name in zfile.namelist():
                if not name.endswith(".yar"):
                    continue
                if self.analyze_entry(name, zfile.read(name)):
                    imported += 1
                else:
                    failed += 1
        logging.info(
            f"YARAify: imported {imported} rule files, {failed} could not be imported"
        )

    def analyze_entry(self, name: str, data: bytes) -> bool:
        """Imports the rules in one file of the YARAify archive.

        A file can hold several rules, and a Yara indicator holds exactly one,
        so each rule is saved with its own source. A community rule set always
        has a few files that don't compile or parse: those are logged and
        skipped rather than stopping the rest of the archive.

        Returns:
            Whether the file imported cleanly.
        """
        try:
            indicator.Yara.import_bulk_rules(data.decode("utf-8"))
        except (
            ValueError,
            plyara.exceptions.ParseError,
            errors.ObjectCreationError,
        ) as error:
            logging.error(f"YARAify: could not import {name}: {error}")
            return False
        return True


taskmanager.TaskManager.register_task(YARAify)
