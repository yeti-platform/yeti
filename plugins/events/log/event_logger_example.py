import json
import logging

from core import taskmanager
from core.events.message import LogMessage
from core.schemas import task


class LoggerExample(task.LogTask):
    _defaults = {
        "name": "EventLoggerExample",
        "description": "Logs events from eventlog bus",
    }

    def run(self, message: LogMessage) -> None:
        if isinstance(message.log, dict):
            logging.info(f"Received event: {json.dumps(message.log)}")
        else:
            logging.info(f"Received event: {message.log}")
        return


taskmanager.TaskManager.register_task(LoggerExample)
