from datetime import datetime

from mongoengine import *
from mongoengine.errors import NotUniqueError

from core.helpers import is_url, is_ip, is_hostname
from core.database import Node
from core.observables import Tag
from core.errors import ObservableValidationError


class Observable(Node):

    value = StringField(required=True, unique=True, sparse=True)
    context = ListField(DictField())
    tags = ListField(EmbeddedDocumentField(Tag))
    last_analyses = DictField()

    created = DateTimeField(default=datetime.now)

    meta = {
        "allow_inheritance": True,
    }

    def __unicode__(self):
        return u"{} ({} context)".format(self.value, len(self.context))

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
                raise ObservableValidationError("{} was not recognized as a viable datatype".format(string))

    @classmethod
    def add_text(cls, text):
        return Observable.guess_type(text).get_or_create(text)

    @classmethod
    def get_or_create(cls, value):
        o = cls(value=value)
        o.clean()
        try:
            return o.save()
        except NotUniqueError:
            return cls.objects.get(value=o.value)

    def add_context(self, context):
        assert 'source' in context
        # uniqueness logic should come here
        return self.modify(add_to_set__context=context)

    def get_tags(self, fresh=True):
        return [t.name for t in self.tags if (t.fresh or not fresh)]

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

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["value", "context", "last_analyses", "created"]}
        i['tags'] = [t.info() for t in self.tags]
        i['id'] = str(self.id)
        return i
