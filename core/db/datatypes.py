from mongoengine import *

class Element(Document):

    value = StringField(required=True, unique=True)
    context = DictField()

    meta = {"allow_inheritance": True}

    @classmethod
    def add_context(cls, value, source, context):
        qs = cls.objects(value=value)
        key = "context__{}".format(source)
        return qs.modify(upsert=True, new=True, **{key: context})

class Url(Element):
    pass
