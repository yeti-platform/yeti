import json
import logging

from core import taskmanager
from core.schemas import task


class LoggerExample(task.LogTask):
    _defaults = {
        "name": "EventLoggerExample",
        "description": "Logs events from eventlog bus",
    }

    def run(self, log: str | dict) -> None:
        if isinstance(log, dict):
            logging.info(f"Received event: {json.dumps(log)}")
        else:
            logging.info(f"Received event: {log}")
        return


taskmanager.TaskManager.register_task(LoggerExample)
