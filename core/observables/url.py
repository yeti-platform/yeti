import re

import urlnorm

from core.observables import Observable
from core.errors import ObservableValidationError
from core.helpers import refang


class Url(Observable):

    def clean(self):
        """Ensures that URLs are canonized before saving"""
        self.value = refang(self.value)
        try:
            if re.match(r"[^:]+://", self.value) is None:  # if no schema is specified, assume http://
                self.value = "http://{}".format(self.value)
            self.value = urlnorm.norm(self.value)
        except urlnorm.InvalidUrl:
            raise ObservableValidationError("Invalid URL: {}".format(self.value))
