from __future__ import unicode_literals

import re

from mongoengine import *

from core.observables import Observable


class Path(Observable):

    fs = StringField(verbose_name="Filesystem")

    # TODO: Use a smarter regex    
    regex = re.compile(r"""([A-Z]:\\|/)""")

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [("fs", "Filesystem")]

    @staticmethod
    def check_type(txt):
        if Path.regex.match(txt):
            return True
        else:
            return False
