from __future__ import unicode_literals

from mongoengine import StringField, ListField
from flask_mongoengine.wtf import model_form
from flask import url_for

from core.database import Node, TagListField, EntityListField
from core.observables import Tag


class Entity(Node):

    VERB_DICT = {
        "Malware": {"Actor": "Used by", "TTP": "Leverages"},
        "Actor": {"Malware": "Uses", "TTP": "Leverages"},
        "Company": {},
        "TTP": {"Actor": "Leveraged by", "Malware": "Observed in"},
    }

    DISPLAY_FIELDS = [("name", "Name"), ("tags", "Tags")]

    name = StringField(verbose_name="Name", required=True, unique=True, sparse=True, max_length=1024)
    description = StringField(verbose_name="Description")
    tags = ListField(StringField(), verbose_name="Relevant tags")

    meta = {
        "allow_inheritance": True,
        "indexes": [
            "tags"
        ],
        "ordering": ["name"],
    }

    def clean(self):
        tags = []
        for t in self.tags:
            if t:
                tags.append(Tag.get_or_create(name=t.lower().strip()))
        self.tags = [t.name for t in tags]

    @classmethod
    def get_form(klass, override=None):
        if override:
            klass = override
        form = model_form(klass, exclude=klass.exclude_fields)
        form.tags = TagListField("Tags that will link to this entity")
        form.links = EntityListField("Bind to entities")

        return form

    def __unicode__(self):
        return u"{}".format(self.name)

    def action(self, target, source, verb=None):
        if not verb:
            if self.__class__.name == target.__class__.__name__:
                verb = "Related {}".format(self.__class__.__name__)
            else:
                verb = Entity.VERB_DICT.get(self.__class__.__name__, {}).get(target.__class__.__name__, "Relates to")
        self.active_link_to(target, verb, source)

    def generate_tags(self):
        return []

    def info(self):
        i = {"name": self.name, "description": self.description, "tags": self.tags}
        i['url'] = url_for("api.Entity:post", id=str(self.id), _external=True)
        i['human_url'] = url_for("frontend.EntityView:get", id=str(self.id), _external=True)
        return i
