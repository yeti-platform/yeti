from datetime import datetime

from mongoengine import *
from core.helpers import is_url, is_ip, is_hostname
from core.datatypes import Tag

class Element(Document):

    value = StringField(required=True, unique=True)
    context = ListField(DictField())
    tags = ListField(EmbeddedDocumentField(Tag))
    last_analyses = DictField()

    created = DateTimeField(default=datetime.now)

    meta = {"allow_inheritance": True}

    @staticmethod
    def guess_type(string):
        from core.datatypes import Url, Ip, Hostname
        if string and string.strip() != '':
            if is_url(string):
                return Url
            elif is_ip(string):
                return Ip
            elif is_hostname(string):
                return Hostname
            else:
                raise ValueError("{} was not recognized as a viable datatype".format(string))

    @classmethod
    def add_text(cls, text):
        return Element.guess_type(text).get_or_create(text)

    @classmethod
    def get_or_create(cls, value):
        o = cls(value=value)
        o.clean()
        try:
            o = cls.objects.get(value=o.value)
        except DoesNotExist:
            o.save()
        return o

    def add_context(self, context):
        assert 'source' in context
        # uniqueness logic should come here
        if context not in self.context:
            return self.modify(add_to_set__context=context)
        return self

    def tag(self, new_tags):
        if isinstance(new_tags, (str, unicode)):
            new_tags = [new_tags]

        for new_tag in new_tags:
            if new_tag.strip() != '':
                if self.objects(id=self.id, tags__name=new_tag).count() == 1:
                    self.bjects(id=self.id, tags__name=new_tag).modify(new=True, set__tags__S__fresh=True, set__tags__S__last_seen=datetime.now())
                    return self.reload()
                else:
                    return self.modify(add_to_set__tags=Tag(name=new_tag))
        return self

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
        return Element.objects(id__in=ids)

    def __unicode__(self):
        return u"{} ({} context)".format(self.value, len(self.context))
