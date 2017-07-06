from __future__ import unicode_literals

from mongoengine import StringField

from core.observables import Observable


class Text(Observable):

    record_type = StringField()

    @staticmethod
    def check_type(txt):
        return True
