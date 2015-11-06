import re

import urlnorm

from core.observables import Observable
from core.errors import ObservableValidationError


class Url(Observable):

    def clean(self):
        """Ensures that URLs are canonized before saving"""
        try:
            if re.match("[a-zA-Z]+://", self.value) is None:
                self.value = "http://{}".format(self.value)
            self.value = urlnorm.norm(self.value)
        except urlnorm.InvalidUrl:
            raise ObservableValidationError("Invalid URL: {}".format(self.value))
