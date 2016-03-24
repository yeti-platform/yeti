from mongoengine import StringField, ListField
from flask.ext.mongoengine.wtf import model_form
from flask import url_for

from core.database import Node, TagListField, EntityListField


class Entity(Node):

    VERB_DICT = {
        "Malware": { "Actor": "Used by", "TTP": "Leverages"},
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
        ]
    }

    @classmethod
    def get_form(klass, override=None):
        if override:
            klass = override
        form = model_form(klass, exclude=klass.exclude_fields)
        form.tags = TagListField("Relevant tags (most precise only)")
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
        self.link_to(target, verb, source)

    def generate_tags(self):
        return []
