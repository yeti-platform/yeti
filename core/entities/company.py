from __future__ import unicode_literals

from mongoengine import DictField

from core.entities import Entity


class Company(Entity):

    rdap = DictField(verbose_name="RDAP")

    DISPLAY_FIELDS = Entity.DISPLAY_FIELDS + [("rdap", "RDAP")]

    def info(self):
        i = Entity.info(self)
        i["rdap"] = self.rdap
        i["type"] = "Company"
        return i
