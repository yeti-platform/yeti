from __future__ import unicode_literals

from mongoengine import StringField
import yara

from core.indicators import Indicator
from core.errors import IndicatorValidationError

rule_template = """rule yeti_rule
{
    meta:
        description = "This is just an example"
        more_info = "http://yara.readthedocs.org/en/v3.4.0/writingrules.html#hexadecimal-strings"

    strings:
        $hex1 = { 6A 40 68 ?? 30 00 [4-6] 6A 14 8D 91 }
        $string1 = "UVODFRYSIHLNWPEJXQZAKCBGMT" wide ascii
        $regex1 = /md5: [0-9a-zA-Z]{32}/

    condition:
        all of ($hex*) and ($string1 or $regex1)
}"""


class Yara(Indicator):

    pattern = StringField(required=True, verbose_name="Pattern", default=rule_template)

    def clean(self):
        try:
            yara.compile(source=self.pattern)
        except (yara.SyntaxError, yara.Error) as e:
            raise IndicatorValidationError("Yara compilation error: {}".format(e))

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
            if isinstance(value, unicode):
                value = value.encode('utf-8')
            matches = self.compiled_yara.match(data=value)
            return True if matches else False
