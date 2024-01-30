from datetime import timedelta
from typing import Optional

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import indicator, task
from core.schemas.observable import Observable
from core.schemas.tag import Tag
from core.schemas.graph import TagRelationship
import datetime

class ExpireTags(task.AnalyticsTask):

    _defaults = {
        "name": "ExpireTags",
        "description": "Expires tags in observables",
        "frequency": timedelta(hours=12),
    }

    def run(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        relationships, total = TagRelationship.filter({"expires": f"<{now}"})
        for rel in relationships:
            rel.fresh = False
            rel.save()


taskmanager.TaskManager.register_task(ExpireTags)
