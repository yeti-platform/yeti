from mongoengine import *
from datetime import datetime

class Element(Document):

    value = StringField(required=True, unique=True)
    context = DictField()

    meta = {"allow_inheritance": True}

    @classmethod
    def add_context(cls, value, source, context):
        qs = cls.objects(value=value)
        key = "context__{}".format(source)
        return qs.modify(upsert=True, new=True, **{key: context})

    def tag(self, tag):
        pass

    def __unicode__(self):
        return u"{} ({} context)".format(self.value, len(self.context))

class LinkHistory(EmbeddedDocument):

    tag = StringField()
    description = StringField()
    timestamp = DateTimeField()

class Link(Document):

    src = ReferenceField(Element, required=True, reverse_delete_rule=CASCADE)
    dst = ReferenceField(Element, required=True, reverse_delete_rule=CASCADE, unique_with='src')
    history = SortedListField(EmbeddedDocumentField(LinkHistory), ordering='timestamp', reverse=True)

    @staticmethod
    def connect(src, dst):
        try:
            l = Link(src=src, dst=dst).save()
        except NotUniqueError as e:
            l = Link.objects.get(src=src, dst=dst)
        return l

    def add_history(self, tag, description, timestamp=None):
        if not timestamp:
            timestamp = datetime.utcnow()

        if len(self.history) == 0:
            self.history.insert(0, LinkHistory(tag=tag, description=description, timestamp=timestamp))
            return self.save()

        last = self.history[0]
        if description == last.description:  # Description is unchanged, do nothing
            return self
        else:  # Link description has changed, insert in link history
            self.history.insert(0, LinkHistory(tag=tag, description=description, timestamp=timestamp))
            if last.timestamp > timestamp:  # we're entering an out-of-order element, list will need sorting
                self.history.sort(key=lambda x: x.timestamp, reverse=True)

        return self.save()


class Url(Element):
    pass

class Ip(Element):
    pass

class Hostname(Element):
    pass
