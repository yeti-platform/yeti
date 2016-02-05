from mongoengine import StringField, ListField
from flask.ext.mongoengine.wtf import model_form

from core.database import Node, Link, TagListField


class Entity(Node):

    name = StringField(verbose_name="Name", required=True, unique=True, sparse=True, max_length=1024)
    description = StringField(verbose_name="Description")
    tags = ListField(StringField(), verbose_name="Relevant tags")

    meta = {
        "allow_inheritance": True,
    }

    @classmethod
    def get_form(klass):
        form = model_form(klass, exclude=klass.exclude_fields)
        form.tags = TagListField("Relevant tags")
        return form

    def __unicode__(self):
        return u"{}".format(self.name)

    def action(self, verb, target, source):
        self.link_to(target, verb, source)

    def generate_tags(self):
        raise NotImplementedError("This method must be implemented in subclasses")
