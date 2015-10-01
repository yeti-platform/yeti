from mongoengine import *
from core.db.mongoengine_extras import TimedeltaField
from datetime import datetime, timedelta

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

    created = DateTimeField(default=datetime.now)

    meta = {"allow_inheritance": True}

    @classmethod
    def get_or_create(cls, value):
        return cls.objects(value=value).modify(upsert=True, new=True, value=value)

    def add_context(self, context):
        assert 'source' in context
        # uniqueness logic should come here
        if context not in self.context:
            print self.update(add_to_set__context=context)
            self.context.append(context)
        return self

    def tag(self, new_tags):
        if isinstance(new_tags, (str, unicode)):
            new_tags = [new_tags]

        for new_tag in new_tags:
            for tag in self.tags:
                if tag.name == new_tag:
                    tag.last_seen = datetime.now()
                    tag.fresh = True
                    return self.save()
            else:
                if new_tag.strip() != '':
                    t = Tag(name=new_tag)
                    self.update(add_to_set__tags=t)
                    self.tags.append(t)
        return self

    def check_tags(self):
        for tag in self.tags:
            if tag.expiration and (tag.last_seen + tag.expiration) < datetime.now():
                tag.fresh = False
        return self.save()

    def fresh_tags(self):
        return [tag for tag in self.tags if tag.fresh]

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
