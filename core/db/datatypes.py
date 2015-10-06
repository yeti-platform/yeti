from datetime import datetime, timedelta
import re

from mongoengine import *
import urlnorm
import idna

from core.db.mongoengine_extras import TimedeltaField
from core.helpers import is_url, is_ip, is_hostname

class Tag(EmbeddedDocument):

    name = StringField()
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)
    expiration = TimedeltaField(default=timedelta(days=365))
    fresh = BooleanField(default=True)

    def __unicode__(self):
        return u"{} ({})".format(self.name, "fresh" if self.fresh else "old")

class Element(Document):

    value = StringField(required=True, unique=True)
    context = ListField(DictField())
    tags = ListField(EmbeddedDocumentField(Tag))
    last_analyses = DictField()

    created = DateTimeField(default=datetime.now)

    meta = {"allow_inheritance": True}

    @staticmethod
    def guess_type(string):
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
    def get_or_create(cls, value):
        return cls.objects(value=value).modify(upsert=True, new=True, value=value).save()

    def add_context(self, context):
        assert 'source' in context
        # uniqueness logic should come here
        if context not in self.context:
            self.update(add_to_set__context=context)
            self.context.append(context)
        return self

    def tag(self, new_tags):
        if isinstance(new_tags, (str, unicode)):
            new_tags = [new_tags]

        for new_tag in new_tags:
            if new_tag.strip() != '':
                if self.__class__.objects(id=self.id, tags__name=new_tag).count() == 1:
                    self.__class__.objects(id=self.id, tags__name=new_tag).update(set__tags__S__fresh=True, set__tags__S__last_seen=datetime.now())
                else:
                    t = Tag(name=new_tag)
                    self.update(add_to_set__tags=t)
        self.reload()
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
        self.update(**{"set__last_analyses__{}".format(module_name): ts})
        self.reload()

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

class LinkHistory(EmbeddedDocument):

    tag = StringField()
    description = StringField()
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)

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
        # this is race-condition prone... think of a better way to do this
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

    def clean(self):
        """Ensures that URLs are canonized before saving"""
        try:
            if not is_url(self.value):
                raise ValidationError("Invalid URL (is_url={}): {}".format(is_url(self.value), self.value))
            if re.match("[a-zA-Z]+://", self.value) is None:
                self.value = "http://{}".format(self.value)
            self.value = urlnorm.norm(self.value)
        except urlnorm.InvalidUrl as e:
            raise ValidationError("Invalid URL: {}".format(self.value))

class Ip(Element):
    pass

class Hostname(Element):

    def clean(self):
        """Performs some normalization on hostnames before saving to the db"""
        try:
            self.value = Hostname.normalize(self.value)
        except Exception as e:
            raise ValidationError("Invalid hostname: {}".format(self.value))

    @staticmethod
    def normalize(hostname):
        if not is_hostname(hostname):
            raise ValidationError("Invalid Hostname (is_hostname={}): {}".format(is_hostname(hostname), hostname))
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        hostname = unicode(idna.encode(hostname.lower()))
        return hostname
