from __future__ import unicode_literals

from flask_mongoengine.wtf import model_form
from mongoengine import *


from core.observables import Observable
from core.database import StringListField


class File(Observable):

    value = StringField(verbose_name="Value")
    mime_type = StringField(verbose_name="MIME type")
    hashes = ListField(DictField(), verbose_name="Hashes")
    body = ReferenceField("AttachedFile")
    filenames = ListField(StringField(), verbose_name="Filenames")

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [("mime_type", "MIME Type")]
    exclude_fields = Observable.exclude_fields + ['hashes', 'body']

    @classmethod
    def get_form(klass):
        form = model_form(klass, exclude=klass.exclude_fields)
        form.filenames = StringListField("Filenames")
        return form

    @staticmethod
    def check_type(txt):
        return True

    def info(self):
        i = Observable.info(self)
        i['mime_type'] = self.mime_type
        i['hashes'] = self.hashes
        return i
