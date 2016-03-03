from core.web.frontend.generic import GenericView
from core.indicators import Indicator, Regex
from core.entities import Entity


class IndicatorsView(GenericView):
    klass = Indicator
    subclass_map = {
        'regex': Regex,
    }

    def post_save(self, e, request):
        links = list(Entity.objects(name__in=set(request.form.get('links', '').split(','))))
        for l in links:
            e.action(l, "web interface")
