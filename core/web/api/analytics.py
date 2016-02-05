from flask.ext.login import current_user

from core.observables import Observable
from core.web.api.crud import CrudApi
from core import analytics
from core.analytics_tasks import schedule
from core.web.api.api import render
from core.web.helpers import get_object_or_404, find_method


class ScheduledAnalytics(CrudApi):
    template = 'scheduled_analytics_api.html'
    objectmanager = analytics.ScheduledAnalytics

    def post(self, id, action):
        method = find_method(self, action, 'action')

        return method(id)

    def refresh(self, id):
        schedule.delay(id)

        return render({"id": id})

    def toggle(self, id):
        a = self.objectmanager.objects.get(id=id)
        a.enabled = not a.enabled
        a.save()

        return render({"id": id, "status": a.enabled})


class OneShotAnalytics(CrudApi):
    template = "oneshot_analytics_api.html"
    objectmanager = analytics.OneShotAnalytics

    def index(self):
        data = []

        for obj in self.objectmanager.objects.all():
            info = obj.info()

            info['available'] = True
            if hasattr(obj, 'settings') and not current_user.has_settings(obj.settings):
                info['available'] = False

            data.append(info)

        return render(data, template=self.template)

    def post(self, id, action):
        method = find_method(self, action, 'action')
        analytics = get_object_or_404(self.objectmanager, id=id)

        return method(analytics)

    def toggle(self, id):
        analytics = get_object_or_404(self.objectmanager, id=id)
        analytics.enabled = not analytics.enabled
        analytics.save()

        return render({"id": analytics.id, "status": analytics.enabled})

    def run(self, id):
        analytics = get_object_or_404(self.objectmanager, id=id)
        args = self.parser.parse_args()
        observable = get_object_or_404(Observable, id=args['id'])

        return render(analytics.run(observable, current_user.settings).to_mongo())

    def status(self, id):
        results = analytics.AnalyticsResults.objects.get(id=id)

        nodes_id = set()
        nodes = list()
        links = list()
        for link in results.results:
            for node in (link.src, link.dst):
                if node.id not in nodes_id:
                    nodes_id.add(node.id)
                    nodes.append(node.to_mongo())
            links.append(link.to_dict())

        results = results.to_mongo()
        results['results'] = {'nodes': nodes, 'links': links}

        return render(results)
