import json
import logging

from core import taskmanager
from core.schemas import task


class LoggerExample(task.LogTask):
    _defaults = {
        "name": "EventLoggerExample",
        "description": "Logs events from eventlog bus",
    }

    def run(self, params: dict) -> None:
        logging.info(f"Received event: {json.dumps(params)}")
        return


taskmanager.TaskManager.register_task(LoggerExample)
