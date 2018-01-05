from __future__ import unicode_literals

from core.web.frontend.generic import GenericView
from core.entities import Entity, TTP, Actor, Company, Malware, Campaign, ExploitKit, Exploit


class EntityView(GenericView):

    klass = Entity
    subclass_map = {
        'ttp': TTP,
        'actor': Actor,
        'company': Company,
        'malware': Malware,
        'campaign': Campaign,
        'exploitkit': ExploitKit,
        'exploit': Exploit
    }

    def post_save(self, e, request):
        links = list(
            Entity.objects(
                name__in=set(request.form.get('links', '').split(','))))
        for l in links:
            e.action(l, "web interface")
