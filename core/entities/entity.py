from mongoengine import StringField

from core.database import Node, Link


class Entity(Node):

    name = StringField(verbose_name="Name", required=True, unique=True, sparse=True, max_length=255)
    description = StringField(verbose_name="Description")

    meta = {
        "allow_inheritance": True,
    }

    def __unicode__(self):
        return u"{}".format(self.name)

    def action(self, verb, target, description=None):
        Link.connect(self, target).add_history(verb, description)

    def generate_tags(self):
        raise NotImplementedError("This method must be implemented in subclasses")
