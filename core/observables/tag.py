import re
from datetime import datetime, timedelta

from mongoengine import *

from core.config.mongoengine_extras import TimeDeltaField
from core.database import Node
from core.errors import TagValidationError


class Tag(Node):
    name = StringField(required=True, unique=True)
    count = IntField(required=True, default=0)
    created = DateTimeField(default=datetime.now)
    produces = ListField(ReferenceField("Tag", reverse_delete_rule=PULL))
    replaces = ListField(StringField())

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["name", "count", "created", "replaces"]}
        i['id'] = str(self.id)
        i['produces'] = [tag.name for tag in self.produces]
        return i

    def add_replaces(self, tags):
        if isinstance(tags, (str, unicode)):
            tags = [tags]
        self.replaces += list(set(tags + self.replaces))
        return self.save()

    def add_produces(self, tags):
        if isinstance(tags, (str, unicode)):
            tags = [Tag.get_or_create(name=tags)]
        else:
            tags = [Tag.get_or_create(name=t) for t in tags]

        self.produces = tags
        return self.save()

    def clean(self):
        self.name = re.sub("[^a-z0-9\-_ ]", "", self.name.lower())
        self.name = re.sub(" ", "_", self.name)
        if not self.name:
            raise TagValidationError("{} is not a valid tag. Valid chars = [a-z0-9\\-_]".format(repr(self.name)))
        self.produces = list(set(self.produces))

    def __unicode__(self):
        return self.name


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
