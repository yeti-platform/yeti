from datetime import datetime, timedelta

from mongoengine import *

from core.config.mongoengine_extras import TimeDeltaField


class Tag(EmbeddedDocument):

    name = StringField()
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)
    expiration = TimeDeltaField(default=timedelta(days=365))
    fresh = BooleanField(default=True)

    def __unicode__(self):
        return u"{} ({})".format(self.name, "fresh" if self.fresh else "old")

    def info(self):
        return {k: v for k, v in self._data.items() if k in ["name", "first_seen", "last_seen", "fresh"]}
