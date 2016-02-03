from core.web.frontend.generic import GenericView
from core.entities import Entity, TTP, Actor, Company, Malware


class EntitiesView(GenericView):
    klass = Entity
    subclass_map = {
        'ttp': TTP,
        'actor': Actor,
        'company': Company,
        'malware': Malware,
    }
