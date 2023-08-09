from __future__ import unicode_literals

import re
from datetime import datetime, timedelta

from core.config.config import yeti_config
from core.config.mongoengine_extras import TimeDeltaField
from core.database import Node
from core.errors import TagValidationError
from core.helpers import iterify
from mongoengine import *


class Tag(Node):
    name = StringField(required=True, unique=True)
    count = IntField(required=True, default=0)
    created = DateTimeField(default=datetime.utcnow)
    produces = ListField(ReferenceField("Tag", reverse_delete_rule=PULL))
    replaces = ListField(StringField())
    default_expiration = TimeDeltaField(
        default=timedelta(seconds=yeti_config.get("tag", "default_tag_expiration"))
    )

    meta = {"ordering": ["name"], "indexes": ["name", "replaces"]}

    def __unicode__(self):
        return self.name

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["name", "count", "created", "replaces"]
        }
        i["id"] = str(self.id)
        i["produces"] = [tag.name for tag in self.produces]
        i["default_expiration"] = self.default_expiration.total_seconds()
        i["default_expiration_str"] = str(self.default_expiration)
        return i

    def add_replaces(self, tags):
        self.replaces += list(set(iterify(tags) + self.replaces))
        return self.save()

    def add_produces(self, tags):
        self.produces = [Tag.get_or_create(name=t) for t in iterify(tags)]
        return self.save()

    def clean(self):
        self.name = re.sub("[^a-z0-9\-_ ]", "", self.name.lower())
        self.name = re.sub(" ", "_", self.name)
        if not self.name:
            raise TagValidationError(
                "{} is not a valid tag. Valid chars = [a-z0-9\\-_]".format(
                    repr(self.name)
                )
            )
        self.produces = list(set(self.produces))


class ObservableTag(EmbeddedDocument):
    name = StringField(required=True)
    first_seen = DateTimeField(default=datetime.utcnow)
    last_seen = DateTimeField(default=datetime.utcnow)
    expiration = TimeDeltaField(
        default=timedelta(seconds=yeti_config.get("tag", "default_tag_expiration"))
    )
    fresh = BooleanField(default=True)

    def __unicode__(self):
        return "{}".format(self.name)

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["first_seen", "last_seen", "fresh", "name"]
        }
        return i
