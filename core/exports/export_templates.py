from mongoengine import *
from jinja2 import Template


class ExportTemplate(object):
    name = StringField(required=True, max_length=255, verbose_name="Name")
    template = StringField(required=True)

    def render(elements):
        t = Template(self.template)
        return t.render(elements=elements)
