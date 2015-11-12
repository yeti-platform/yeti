from datetime import datetime

from mongoengine import *



class Entity(Document):

    name = StringField(required=True, unique=True)
    description = StringField()

    meta = {"allow_inheritance": True}

    @classmethod
    def get_or_create(cls, value):
        e = cls(value=value)
        e.clean()
        return cls.objects(value=e.name).modify(upsert=True, new=True, name=o.name)


class EntityLink(Document):

    src = ReferenceField(Entity, required=True, reverse_delete_rule=CASCADE)
    dst = ReferenceField(Entity, required=True, reverse_delete_rule=CASCADE, unique_with='src')
    verb = StringField()
    description = StringField()
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)

    @staticmethod
    def connect(src, dst):
        try:
            l = EntityLink(src=src, dst=dst).save()
        except NotUniqueError:
            l = EntityLink.objects.get(src=src, dst=dst)
            l.last_seen = datetime.now()
            l.save()
        return l
