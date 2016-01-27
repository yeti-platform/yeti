from flask_restful import reqparse

from core.observables import Observable
from core.web.api.crud import CrudApi
from core.analytics import ScheduledAnalytics, OneShotAnalytics, AnalyticsResults
from core.analytics_tasks import schedule
from core.web.api.api import render
from core.web.helpers import get_object_or_404, find_method


class ScheduledAnalyticsApi(CrudApi):
    template = 'scheduled_analytics_api.html'
    objectmanager = ScheduledAnalytics

    def post(self, id, action):
        method = find_method(self, action, 'action')

        return method(id)

    def refresh(self, id):
        schedule.delay(id)

        return render({"id": id})

    def toggle(self, id):
        a = ScheduledAnalytics.objects.get(id=id)
        a.enabled = not a.enabled
        a.save()

        return render({"id": id, "status": a.enabled})


class OneShotAnalyticsApi(CrudApi):
    template = "oneshot_analytics_api.html"
    objectmanager = OneShotAnalytics

    parser = reqparse.RequestParser()
    parser.add_argument('id', required=True, help="You must specify an ID.")

    def post(self, id, action):
        method = find_method(self, action, 'action')
        analytics = get_object_or_404(OneShotAnalytics, id=id)

        return method(analytics)

    def toggle(self, analytics):
        analytics.enabled = not analytics.enabled
        analytics.save()

        return render({"id": analytics.id, "status": analytics.enabled})

    def run(self, analytics):
        args = self.parser.parse_args()
        observable = get_object_or_404(Observable, id=args['id'])

        return render(analytics.run(observable).to_mongo())

    def status(self, analytics):
        args = self.parser.parse_args()
        results = AnalyticsResults.objects.get(id=args['id'])

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
