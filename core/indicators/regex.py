import re

from core.indicators import Indicator


class Regex(Indicator):

    def __init__(self, *args, **kwargs):
        super(Regex, self).__init__(*args, **kwargs)
        if self.pattern:
            try:
                self.compiled_regex = re.compile(self.pattern)
                self.error = False
            except Exception as e:
                self.compiled_regex = None
                self.error = e

    def match(self, value):
        if not self.error:
            return True if self.compiled_regex.search(value) else False
