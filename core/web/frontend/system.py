import threading
import re

from flask_classy import FlaskView, route
from core.web.helpers import requires_role
from flask import render_template, redirect, request, flash
import psutil
import subprocess

from core.config.celeryctl import celery_app
from core.scheduling import ScheduleEntry

class Inspector(threading.Thread):

    def __init__(self, inspect, method, *args, **kwargs):
        super(Inspector, self).__init__(*args, **kwargs)
        self.inspect = inspect
        self.method = method
        self.result = None

    def run(self):
        self.result = getattr(self.inspect, self.method)()


class SystemView(FlaskView):

    INSPECT_METHODS=('stats', 'active_queues', 'registered', 'scheduled',
                       'active', 'reserved', 'revoked', 'conf')

    @requires_role('admin')
    @route("/restart/worker/<name>", methods=["GET"])
    def restart_worker(self, name):
        response = celery_app.control.broadcast(
            'pool_restart',
            arguments={'reload': True},
            destination=[name],
            reply=True,
        )
        if response and 'ok' in response[0][name]:
            flash("Worker {} restarted successfully".format(response[0][name]), "success")
        else:
            flash("Failed to restart worker {}".format(response[0][name]), "danger")

        return redirect(request.referrer)

    @requires_role('admin')
    @route("/restart/beat")
    def restart_beat(self):
        pids = psutil.pids()

        for pid in pids:
            try:
                cmd = " ".join(psutil.Process(pid).cmdline())
                if "celery -A core.config.celeryctl beat" in cmd:
                    break
            except psutil.AccessDenied:
                pass
        else:
            pid = None

        if pid:
            psutil.Process(pid).terminate()
            p = subprocess.Popen(cmd.split(" "))
            flash("Scheduler restarted successfully (PID: {})".format(p.pid), "success")
        else:
            flash("Error restaring scheduler", "danger")

        return redirect(request.referrer)



    @requires_role('admin')
    def index(self):
        results = {}
        inspect = celery_app.control.inspect(timeout=5, destination=None)

        ts = []
        for method in SystemView.INSPECT_METHODS:
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
                active[key] = {
                    "running": [ScheduleEntry.objects.get(id=re.sub(r"[^0-9a-f]", "", i['args'])) for i in results["active"][key]],
                }

        return render_template(
            "system/system.html",
            registered=registered,
            active=active,
            )
