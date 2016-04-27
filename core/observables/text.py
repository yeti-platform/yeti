from mongoengine import *

from core.observables import Observable


class Text(Observable):

    @staticmethod
    def check_type(txt):
        return True
