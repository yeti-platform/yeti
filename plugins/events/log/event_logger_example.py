import json
import logging

from core import taskmanager
from core.schemas import task


class EventLoggerExample(task.EventLogTask):
    _defaults = {
        "name": "EventLoggerExample",
        "description": "Logs events from eventlog bus",
    }

    def run(self, params: dict) -> None:
        logging.info(f"Received event: {json.dumps(params)}")
        return
    
taskmanager.TaskManager.register_task(EventLoggerExample)
