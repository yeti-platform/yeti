from core.web.frontend.generic import GenericView
from core.indicators import Indicator, Regex


class IndicatorsView(GenericView):
    klass = Indicator
    subclass_map = {
        'regex': Regex,
    }
