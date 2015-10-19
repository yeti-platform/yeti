import re

from mongoengine import *
import urlnorm

from core.datatypes import Element
from core.helpers import is_url

class Url(Element):

    def clean(self):
        """Ensures that URLs are canonized before saving"""
        try:
            if re.match("[a-zA-Z]+://", self.value) is None:
                self.value = "http://{}".format(self.value)
            self.value = urlnorm.norm(self.value)
        except urlnorm.InvalidUrl:
            raise ValidationError("Invalid URL: {}".format(self.value))
