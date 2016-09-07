from __future__ import unicode_literals

import re
from urlparse import urlparse

import urlnorm
from mongoengine import DictField

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

    parsed_url = DictField()

    def clean(self):
        """Ensures that URLs are canonized before saving"""
        self.value = refang(self.value.strip())
        try:
            if re.match(r"[^:]+://", self.value) is None:
                # if no schema is specified, assume http://
                self.value = u"http://{}".format(self.value)
            self.value = urlnorm.norm(self.value)
            self.parse()
        except urlnorm.InvalidUrl:
            raise ObservableValidationError("Invalid URL: {}".format(self.value))
        except UnicodeDecodeError:
            raise ObservableValidationError("Invalid URL (UTF-8 decode error): {}".format(self.value))


    def parse(self):
        parsed = urlparse(self.value)

        self.parsed_url = {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc.split(":")[0],
            "port": parsed.port if parsed.port else "80",
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment
        }

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
