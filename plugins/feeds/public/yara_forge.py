import re
from datetime import timedelta
from io import BytesIO, StringIO
from typing import ClassVar
from zipfile import ZipFile

import yara

from core import taskmanager
from core.schemas import indicator, task


class YARAForge(task.FeedTask):
    __SOURCE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"

    _defaults = {
        "frequency": timedelta(days=1),
        "name": "YARA Forge",
        "description": "This feed contains yara rules of https://yarahq.github.io/",
        "source": "",
    }

    def run(self):
        response = self._make_request(self.__SOURCE, no_cache=True)
        if not response:
            return
        zip_file = BytesIO(response.content)
        with ZipFile(zip_file) as zfile:
            for name in zfile.namelist():
                if name.endswith(".yar"):
                    all_text = zfile.read(name)
                    rules = re.split(
                        r"^(?:import\s+\".*?\"\s*\n)*^rule([^{]*){([^:]*):\n*\s*((?:.*\n)*?)\s*(?:strings:\s*((?:.*\n)*?)\s*)?condition:\s*((?:.*\n)*?)\s*\}",
                        all_text.decode())
                    for r in rules:
                        self.analyze(yara.compile(r))

    def analyze(self, rule:str):
        print(rule)


taskmanager.TaskManager.register_task(YARAForge)
