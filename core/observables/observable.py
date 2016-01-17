from datetime import datetime
import operator

from mongoengine import *

from core.helpers import is_url, is_ip, is_hostname
from core.database import Node
from core.observables import ObservableTag, Tag
from core.errors import ObservableValidationError


class Observable(Node):

    value = StringField(verbose_name="Value", required=True, unique=True, sparse=True)
    sources = ListField(StringField(), verbose_name="Sources")
    description = StringField(verbose_name="Description")
    context = ListField(DictField(), verbose_name="Context")
    tags = ListField(EmbeddedDocumentField(ObservableTag), verbose_name="Tags")
    last_analyses = DictField(verbose_name="Last analyses")

    created = DateTimeField(default=datetime.now)

    exclude_fields = ['sources', 'context', 'last_analyses', 'created', 'tags']

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
        return Observable.guess_type(text).get_or_create(value=text)

    @staticmethod
    def change_all_tags(old_tags, new_tag):
        if isinstance(old_tags, (str, unicode)):
            old_tags = [old_tags]

        for o in Observable.objects(tags__name__in=old_tags):
            for old_tag in old_tags:
                o.change_tag(old_tag, new_tag)

    def add_context(self, context):
        assert 'source' in context
        context = {k: v for k, v in sorted(context.items(), key=operator.itemgetter(0))}
        self.modify(add_to_set__context=context)
        return self.reload()

    def add_source(self, source):
        return self.modify(add_to_set__sources=source)

    def get_tags(self, fresh=True):
        return [t.name for t in self.tags if (t.fresh or not fresh)]

    def find_tags(self):
        # find related tags and count them
        new_tags = {}
        for tag in self.tags:
            tag = Tag.objects.get(name=tag.name)
            for produces in tag.produces:
                new_tags[produces] = new_tags.get(tag, 0) + 1

        # remove already known tags
        localtags = [tag.name for tag in self.tags]
        for tag in new_tags.copy():
            if tag in localtags:
                new_tags.pop(tag)

        return new_tags

    def has_tag(self, tag_to_search):
        for tag in self.tags:
            if tag.name == tag_to_search:
                return True
        else:
            return False

    def change_tag(self, old_tag, new_tag):
        if not self.modify({"tags__name": old_tag, "tags__name__ne": new_tag}, set__tags__S__name=new_tag):
            self.modify({"tags__name": old_tag}, pull__tags__name=old_tag)
            self.modify({"tags__name": new_tag}, set__tags__S__last_seen=datetime.now())
        return self.reload()

    def tag(self, new_tags):
        if isinstance(new_tags, (str, unicode)):
            new_tags = [new_tags]

        for new_tag in new_tags:
            if new_tag.strip() != '':
                new_tag = Tag(name=new_tag)
                new_tag.clean()

                try:  # check if tag is a replacement
                    tag = Tag.objects.get(replaces=new_tag.name)
                except DoesNotExist:
                    tag = Tag.get_or_create(name=new_tag.name)

                if not self.modify({"tags__name": tag.name}, set__tags__S__fresh=True, set__tags__S__last_seen=datetime.now()):
                    self.modify(push__tags=ObservableTag(name=tag.name))
                    tag.modify(inc__count=1)

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

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["value", "context", "last_analyses", "created", "sources"]}
        i['tags'] = [t.info() for t in self.tags]
        i['id'] = str(self.id)
        i['type'] = self.__class__.__name__
        return i
