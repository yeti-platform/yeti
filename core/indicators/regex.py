import re

from core.indicators import Indicator


class Regex(Indicator):

    def __init__(self, *args, **kwargs):
        super(Regex, self).__init__(*args, **kwargs)
        self.compiled_regex = re.compile(self.pattern)

    def match(self, value):
        return True if self.compiled_regex.search(value) else False
