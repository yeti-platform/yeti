from datetime import datetime

from mongoengine import *
from core.helpers import is_url, is_ip, is_hostname
from core.observables import Tag

class Observable(Document):

    value = StringField(required=True, unique=True)
    context = ListField(DictField())
    tags = ListField(EmbeddedDocumentField(Tag))
    last_analyses = DictField()

    created = DateTimeField(default=datetime.now)

    meta = {"allow_inheritance": True}

    @staticmethod
    def guess_type(string):
        from core.observables import Url, Ip, Hostname
        if string and string.strip() != '':
            if is_url(string):
                return Url
            elif is_ip(string):
                return Ip
            elif is_hostname(string):
                return Hostname
            else:
                raise ValidationError("{} was not recognized as a viable datatype".format(string))

    @classmethod
    def add_text(cls, text):
        return Observable.guess_type(text).get_or_create(text)

    @classmethod
    def get_or_create(cls, value):
        o = cls(value=value)
        o.clean()
        return cls.objects(value=o.value).modify(upsert=True, new=True, value=o.value)

    def add_context(self, context):
        assert 'source' in context
        # uniqueness logic should come here
        return self.modify(add_to_set__context=context)

    def tag(self, new_tags):
        if isinstance(new_tags, (str, unicode)):
            new_tags = [new_tags]

        for new_tag in new_tags:
            if new_tag.strip() != '':
                if self.__class__.objects(id=self.id, tags__name=new_tag).count() == 1:
                    self.__class__.objects(id=self.id, tags__name=new_tag).modify(new=True, set__tags__S__fresh=True, set__tags__S__last_seen=datetime.now())
                else:
                    self.modify(add_to_set__tags=Tag(name=new_tag))
        return self.reload()

    def check_tags(self):
        for tag in self.tags:
            if tag.expiration and (tag.last_seen + tag.expiration) < datetime.now():
                tag.fresh = False
        return self.save()

    def fresh_tags(self):
        return [tag for tag in self.tags if tag.fresh]

    def analysis_done(self, module_name):
        ts = datetime.now()
        return self.modify(**{"set__last_analyses__{}".format(module_name): ts})

    # neighbors

    def incoming(self):
        return [l.src for l in Link.objects(dst=self.id)]

    def outgoing(self):
        return [l.dst for l in Link.objects(src=self.id)]

    def all_neighbors(self):
        ids = set()
        ids |= ({l.src.id for l in Link.objects(dst=self.id)})
        ids |= ({l.dst.id for l in Link.objects(src=self.id)})
        return Observable.objects(id__in=ids)

    def __unicode__(self):
        return u"{} ({} context)".format(self.value, len(self.context))

class LinkHistory(EmbeddedDocument):

    tag = StringField()
    description = StringField()
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)

class Link(Document):

    src = ReferenceField(Observable, required=True, reverse_delete_rule=CASCADE)
    dst = ReferenceField(Observable, required=True, reverse_delete_rule=CASCADE, unique_with='src')
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
