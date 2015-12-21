from datetime import datetime, timedelta

from mongoengine import *

from core.config.mongoengine_extras import TimeDeltaField


class TagName(Document):
    name = StringField(required=True)
    count = IntField(required=True, default=0)
    created = DateTimeField(default=datetime.now)

    def info(self):
        return {k: v for k, v in self._data.items() if k in ["name", "count", "created"]}


class Tag(EmbeddedDocument):

    name = ReferenceField(TagName)
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)
    expiration = TimeDeltaField(default=timedelta(days=365))
    fresh = BooleanField(default=True)

    def __unicode__(self):
        return u"{} ({})".format(self.name, "fresh" if self.fresh else "old")

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["first_seen", "last_seen", "fresh"]}
        i['name'] = self.name.name
        return i
