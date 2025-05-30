import datetime
from datetime import timedelta

from core import taskmanager
from core.schemas import observable, task


class ExpireTags(task.AnalyticsTask):
    _defaults = {
        "name": "ExpireTags",
        "description": "Expires tags in observables",
        "frequency": timedelta(hours=12),
    }

    def run(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        observables, total = observable.Observable.filter(
            query_args={"tags.expires": f"<{now.isoformat()}"},
        )
        for obs in observables:
            obs.expire_tags()


taskmanager.TaskManager.register_task(ExpireTags)
