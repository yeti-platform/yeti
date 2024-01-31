import datetime
from datetime import timedelta

from core import taskmanager
from core.schemas import task
from core.schemas.graph import TagRelationship


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
