from core.web.api.crud import CrudSearchApi, CrudApi
from core.indicators import Indicator


class IndicatorSearchApi(CrudSearchApi):
    template = 'indicator_api.html'
    objectmanager = Indicator


class IndicatorApi(CrudApi):
    template = 'indicator_api.html'
    objectmanager = Indicator
