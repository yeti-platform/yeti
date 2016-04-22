import yara

from core.indicators import Indicator


class Yara(Indicator):

    def __init__(self, *args, **kwargs):
        super(Yara, self).__init__(*args, **kwargs)
        if self.pattern:
            try:
                self.compiled_yara = yara.compile(source=self.pattern)
                self.error = False
            except Exception as e:
                self.compiled_yara = None
                self.error = e

    def match(self, value):
        if not self.error:
            matches = self.compiled_yara.match(data=value)
            return True if matches else False
