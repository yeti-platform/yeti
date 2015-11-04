import re

from core.indicators import Indicator


class Regex(Indicator):

    def match(self, value):
        return True if re.search(self.pattern, value) else False
