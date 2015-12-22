from datetime import datetime, timedelta

from mongoengine import *

from core.config.mongoengine_extras import TimeDeltaField
from core.database import Node


class Tag(Node):
    name = StringField(required=True, unique=True)
    count = IntField(required=True, default=0)
    created = DateTimeField(default=datetime.now)

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["name", "count", "created"]}
        i['id'] = str(self.id)
        return i


class ObservableTag(EmbeddedDocument):

    name = StringField(required=True)
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)
    expiration = TimeDeltaField(default=timedelta(days=365))
    fresh = BooleanField(default=True)

    def __unicode__(self):
        return u"{} ({})".format(self.name, "fresh" if self.fresh else "old")

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["first_seen", "last_seen", "fresh", "name"]}
        return i


class TagGroup(Document):
    name = StringField()
    tags = ListField(Tag)

    def info(self):
        i = {"tags": [t.info() for t in self.tags], "name": self.name}
        i['id'] = str(self.id)
        return i
