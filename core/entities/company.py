from mongoengine import DictField

from core.entities import Entity


class Company(Entity):

    rdap = DictField()
