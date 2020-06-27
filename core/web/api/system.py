import threading

from flask_classy import FlaskView, route
from flask_login import current_user

from core.config.celeryctl import celery_app
from core.config.config import yeti_config
from core.scheduling import ScheduleEntry
from core.web.api.api import render
from core.web.helpers import requires_role


class Inspector(threading.Thread):

    def __init__(self, inspect, method, *args, **kwargs):
        super(Inspector, self).__init__(*args, **kwargs)
        self.inspect = inspect
        self.method = method
        self.result = None

    def run(self):
        self.result = getattr(self.inspect, self.method)()


class System(FlaskView):

    INSPECT_METHODS = ('registered', 'active', 'stats')

    @requires_role('admin')
    @route("/restart/worker/<name>")
    def restart_worker(self, name="all"):
        response = celery_app.control.broadcast(
            'pool_restart',
            arguments={'reload': True},
            destination=[name] if name != "all" else None,
            reply=True,
        )

        nok = []
        for r in response:
            for name in r:
                if 'ok' not in r[name]:
                    nok.append(name)
        if nok:
            nok_list = ', '.join(nok)
            message = 'Some workers failed to restart: {0:s}'.format(nok_list)
            return render({
                'status': 'error',
                'message': message
            })

        message = "Succesfully restarted {0:d} workers".format(len(response))
        return render({
            'status': 'success',
            'message': message
        })

    @requires_role('admin')
    def index(self):
        results = {}
        inspect = celery_app.control.inspect(timeout=5, destination=None)

        ts = []
        for method in System.INSPECT_METHODS:
            t = Inspector(inspect, method)
            t.start()
            ts.append(t)

        for t in ts:
            t.join()
            results[t.method] = t.result

        registered = {}
        if results['registered']:
            for key in results['registered']:
                registered[key] = {
                    "processes": results['stats'][key]["pool"]["processes"],
                    "active": len(results['active'][key]) > 0,
                }

        active = {}
        if results['active']:
            for key in results['active']:
                entries = []
                for item in results["active"][key]:
                    args = item.get("args", [])
                    entries.extend([ScheduleEntry.objects.get(id=id_) for id_ in args])
                active[key] = { "running": [entry.name for entry in entries] }

        return render({
            'registered': registered,
            'active': active
        })

    def config(self):
        if current_user.has_role('admin'):
            config = {
                'auth': dict(yeti_config.auth),
                'mongodb': dict(yeti_config.mongodb),
                'redis': dict(yeti_config.redis),
                'proxy': dict(yeti_config.proxy),
                'logging': dict(yeti_config.logging),
            }
            del config['mongodb']['username']
            del config['mongodb']['password']
        else:
            config = {
                'auth': dict(yeti_config.auth)
            }
        return render(config)
