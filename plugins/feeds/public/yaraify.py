import logging
from datetime import timedelta
from io import BytesIO
from typing import ClassVar
from zipfile import ZipFile

import yara

from core import taskmanager
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
        zip_file = BytesIO(response.content)
        with ZipFile(zip_file) as zfile:
            for name in zfile.namelist():
                if name.endswith(".yar"):
                    self.analyze_entry(zfile.read(name).decode("utf-8"))

    def analyze_entry(self, entry: str):
        logging.debug(f"Yaraify: {entry}")
        try:
            yara_rules = yara.compile(source=entry)
        except yara.SyntaxError as e:
            logging.error(f"Error compiling yara rule: {e}")
            return
        for r in yara_rules:
            ind_obj = indicator.Yara(
                name=f"{r.identifier}",
                pattern=entry,
                diamond=indicator.DiamondModel.capability,
                description=f"{r.meta.get('description', 'N/A')}"
            )

            
            ind_obj.save()


taskmanager.TaskManager.register_task(YARAify)
taskmanager.TaskManager.register_task(YARAify)
