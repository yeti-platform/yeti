from __future__ import unicode_literals

from core.web.api.crud import CrudSearchApi, CrudApi
from core import indicators


class IndicatorSearch(CrudSearchApi):
    objectmanager = indicators.Indicator


class Indicator(CrudApi):
    objectmanager = indicators.Indicator
    subobjects = {
        "regex": indicators.Regex,
        "yara": indicators.Yara,
    }
