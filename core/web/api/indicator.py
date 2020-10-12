from __future__ import unicode_literals

from core.web.api.crud import CrudSearchApi, CrudApi
from core import indicators


class IndicatorSearch(CrudSearchApi):
    template = "indicator_api.html"
    objectmanager = indicators.Indicator


class Indicator(CrudApi):
    template = "indicator_api.html"
    objectmanager = indicators.Indicator
    subobjects = {
        "Regex": indicators.Regex,
        "Yara": indicators.Yara,
    }
