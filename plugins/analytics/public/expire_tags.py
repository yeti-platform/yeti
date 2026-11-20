import datetime
from datetime import timedelta

from core import taskmanager
from core.schemas import observable, task

# Observables with a tag that is still marked fresh but past its expiry date.
# A tag that never expires has `expires: null`, and AQL sorts null below every
# number, so the date comparison alone would match it.
EXPIRED_TAG_KEYS_AQL = """
FOR o IN observables
    FILTER LENGTH(o.tags[* FILTER CURRENT.fresh == true
        AND IS_DATESTRING(CURRENT.expires)
        AND DATE_TIMESTAMP(CURRENT.expires) < @now_ms]) > 0
    RETURN o._key
"""


class ExpireTags(task.AnalyticsTask):
    _defaults = {
        "name": "ExpireTags",
        "description": "Expires tags in observables",
        "frequency": timedelta(hours=12),
    }

    def run(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        keys = list(
            observable.Observable._db.aql.execute(
                EXPIRED_TAG_KEYS_AQL,
                bind_vars={"now_ms": int(now.timestamp() * 1000)},
            )
        )
        for key in keys:
            obs = observable.Observable.get(key)
            if obs is None:  # Deleted since the keys were read.
                continue
            obs.expire_tags()


taskmanager.TaskManager.register_task(ExpireTags)
