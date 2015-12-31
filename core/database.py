import logging

from datetime import datetime

from mongoengine import *
from mongoengine import Q


class LinkHistory(EmbeddedDocument):

    tag = StringField()
    description = StringField()
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)


class Link(Document):

    src = ReferenceField("Node", required=True)
    dst = ReferenceField("Node", required=True, unique_with='src')
    history = SortedListField(EmbeddedDocumentField(LinkHistory), ordering='last_seen', reverse=True)

    def __unicode__(self):
        return u"{} {} {} ({})".format(self.src, self.tag, self.dst, self.description)

    @property
    def tag(self):
        if len(self.history) > 0:
            return self.history[0].tag

    @property
    def description(self):
        if len(self.history) > 0:
            return self.history[0].description

    @property
    def last_seen(self):
        if len(self.history) > 0:
            return self.history[0].last_seen

    @staticmethod
    def connect(src, dst):
        try:
            l = Link(src=src, dst=dst).save()
        except NotUniqueError:
            l = Link.objects.get(src=src, dst=dst)
        return l

    def info(self):
        return {"tag": self.tag, "description": self.description, "id": str(self.id), "src": unicode(self.src), "dst": unicode(self.dst)}

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


class Node(Document):

    meta = {
        "abstract": True,
    }

    @property
    def type(self):
        return self._cls.split(".")[-1:][0]

    @classmethod
    def get_or_create(cls, **kwargs):
        obj = cls(**kwargs)
        obj.clean()
        try:
            return obj.save()
        except NotUniqueError:
            if hasattr(obj, 'name'):
                return cls.objects.get(name=obj.name)
            if hasattr(obj, 'value'):
                return cls.objects.get(value=obj.value)

    @classmethod
    def update(cls, id, data):
        o = cls.objects(id=id).modify(new=True, **data)
        o.clean()
        o.save()

    def incoming(self):
        return [(l, l.src) for l in Link.objects(dst=self)]

    def outgoing(self):
        return [(l, l.dst) for l in Link.objects(src=self)]

    def neighbors(self):
        links = list(set(self.incoming() + self.outgoing()))
        info = {}
        for link, node in links:
            info[node.type] = info.get(node.type, []) + [(link, node)]
        return info

    def delete(self):
        Link.objects(Q(src=self) | Q(dst=self)).delete()
        super(Node, self).delete()

    def to_dict(self):
        return self._fields
