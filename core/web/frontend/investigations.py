from __future__ import unicode_literals

from core.web.frontend.generic import GenericView
from core.investigation import Investigation


class InvestigationsView(GenericView):

    klass = Investigation
