from mongoengine import DictField

from core.entities import Entity


class Company(Entity):

    rdap = DictField(verbose_name="RDAP")

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ['id', 'name', 'rdap']}
        i['type'] = "Company"
        return i
