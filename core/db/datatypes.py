from mongoengine import *
from datetime import datetime

class Element(Document):

    value = StringField(required=True, unique=True)
    context = ListField(DictField())
    tags = ListField(DictField())

    meta = {"allow_inheritance": True}

    @classmethod
    def get_or_create(cls, value):
        return cls.objects(value=value).modify(upsert=True, new=True, value=value)

    def add_context(self, context):
        # uniqueness logic should come here
        assert 'source' in context
        self.update(add_to_set__context=context)

    def tag(self, tag):
        for tag in self.tags:
            pass

    def __unicode__(self):
        return u"{} ({} context)".format(self.value, len(self.context))

class LinkHistory(EmbeddedDocument):

    tag = StringField()
    description = StringField()
    first_seen = DateTimeField()
    last_seen = DateTimeField()

class Link(Document):

    src = ReferenceField(Element, required=True, reverse_delete_rule=CASCADE)
    dst = ReferenceField(Element, required=True, reverse_delete_rule=CASCADE, unique_with='src')
    history = SortedListField(EmbeddedDocumentField(LinkHistory), ordering='last_seen', reverse=True)

    @staticmethod
    def connect(src, dst):
        try:
            l = Link(src=src, dst=dst).save()
        except NotUniqueError as e:
            l = Link.objects.get(src=src, dst=dst)
        return l

    def add_history(self, tag, description, first_seen=None, last_seen=None):
        if not first_seen:
            first_seen = datetime.utcnow()
        if not last_seen:
            last_seen = datetime.utcnow()

        if len(self.history) == 0:
            self.history.insert(0, LinkHistory(tag=tag, description=description, first_seen=first_seen, last_seen=last_seen))
            return self.save()

        last = self.history[0]
        if description == last.description:  # Description is unchanged, do nothing
            self.history[0].last_seen = last_seen
        else:  # Link description has changed, insert in link history
            self.history.insert(0, LinkHistory(tag=tag, description=description, first_seen=first_seen, last_seen=last_seen))
            if last.first_seen > first_seen:  # we're entering an out-of-order element, list will need sorting
                self.history.sort(key=lambda x: x.last_seen, reverse=True)

        return self.save()


class Url(Element):
    pass

class Ip(Element):
    pass

class Hostname(Element):
    pass
