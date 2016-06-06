from __future__ import unicode_literals

import re

import urlnorm

from core.observables import Observable
from core.errors import ObservableValidationError
from core.helpers import refang


class Url(Observable):

    regex = r"""
                (
                  ((?P<scheme>[\w]{2,9}):\/\/)?
                  ([\S]*\:[\S]*\@)?
                  (?P<hostname>((([^/:]+\.)([^/:]+))\.?))
                  (\:[\d]{1,5})?
                  (?P<path>(\/[\S]*)?
                    (\?[\S]*)?
                    (\#[\S]*)?)
                )
            """

    def clean(self):
        """Ensures that URLs are canonized before saving"""
        self.value = refang(self.value.strip())
        try:
            if re.match(r"[^:]+://", self.value) is None:  # if no schema is specified, assume http://
                self.value = u"http://{}".format(self.value)
            self.value = urlnorm.norm(self.value)
        except urlnorm.InvalidUrl:
            raise ObservableValidationError("Invalid URL: {}".format(self.value))

    @staticmethod
    def check_type(txt):
        url = refang(txt)
        match = re.match("^" + Url.regex + "$", url, re.VERBOSE)
        if match:
            url = match.group(1)
            if url.find('/') != -1:
                return match.group(1)
        else:
            return None
