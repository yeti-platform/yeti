from datetime import datetime

from mongoengine import *


class Node(Document):

    meta = {
        "allow_inheritance": True,
        # This should be an abstract class, but mongoengine 0.10.0 cannot reference
        # abstract classes (see: https://github.com/MongoEngine/mongoengine/issues/837)
        # thus breaking the refences in Link... Keep calm and wait for the PR to be closed.
        # "abstract": True,
    }

    @classmethod
    def get_or_create(cls, **kwargs):
        o = cls(**kwargs)
        o.clean()
        return cls.objects(**kwargs).modify(upsert=True, new=True, **kwargs)

    def __unicode__(self):
        return u"{} ({} context)".format(self.value, len(self.context))

    def incoming(self):
        return [l.src for l in Link.objects(dst=self.id)]

    def outgoing(self):
        return [l.dst for l in Link.objects(src=self.id)]

    def all_neighbors(self):
        ids = set()
        ids |= ({l.src.id for l in Link.objects(dst=self.id)})
        ids |= ({l.dst.id for l in Link.objects(src=self.id)})
        return Node.objects(id__in=ids)


class LinkHistory(EmbeddedDocument):

    tag = StringField()
    description = StringField()
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)


class Link(Document):

    src = ReferenceField(Node, required=True, reverse_delete_rule=CASCADE)
    dst = ReferenceField(Node, required=True, reverse_delete_rule=CASCADE, unique_with='src')
    history = SortedListField(EmbeddedDocumentField(LinkHistory), ordering='last_seen', reverse=True)

    @staticmethod
    def connect(src, dst):
        try:
            l = Link(src=src, dst=dst).save()
        except NotUniqueError:
            l = Link.objects.get(src=src, dst=dst)
        return l

    def add_history(self, tag, description=None, first_seen=None, last_seen=None):
        # this is race-condition prone... think of a better way to do this
        if not first_seen:
            first_seen = datetime.utcnow()
        if not last_seen:
            last_seen = datetime.utcnow()

        if len(self.history) == 0:
            return self.modify(push__history=LinkHistory(tag=tag, description=description, first_seen=first_seen, last_seen=last_seen))

        last = self.history[0]
        if description == last.description:  # Description is unchanged, update timestamp
            return self.modify(set__history__0__last_seen=last_seen)
        else:  # Link description has changed, insert in link history
            return self.modify(push__history=LinkHistory(tag=tag, description=description, first_seen=first_seen, last_seen=last_seen))
