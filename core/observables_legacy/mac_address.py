from __future__ import unicode_literals

import re

from core.observables import Observable


class MacAddress(Observable):
    regex = r"(?P<search>(([0-9A-Fa-f]{1,2}[.:-]){5,7}([0-9A-Fa-f]{1,2})))"

    exclude_fields = Observable.exclude_fields

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS

    @classmethod
    def is_valid(cls, match):
        value = match.group("search")
        return len(value) > 0

    def normalize(self):
        value = re.sub(r"[.:\-]", "", self.value).upper()
        self.value = ":".join(value[i : i + 2] for i in range(0, len(value), 2))
