from __future__ import unicode_literals

from core.web.frontend.generic import GenericView
from core.indicators import Indicator, Regex, Yara
from core.entities import Entity


class IndicatorView(GenericView):
    klass = Indicator
    subclass_map = {
        'regex': Regex,
        'yara': Yara,
    }

    def post_save(self, e, request):
        links = list(Entity.objects(name__in=set(request.form.get('links', '').split(','))))
        for l in links:
            e.action(l, "web interface")
