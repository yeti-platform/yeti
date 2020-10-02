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

    INSPECT_METHODS = ("registered", "active", "stats")

    @requires_role("admin")
    @route("/restart/worker/<name>")
    def restart_worker(self, name="all"):
        response = celery_app.control.broadcast(
            "pool_restart",
            arguments={"reload": True},
            destination=[name] if name != "all" else None,
            reply=True,
        )

        nok = []
        for r in response:
            for name in r:
                if "ok" not in r[name]:
                    nok.append(name)
        if nok:
            flash("Some workers failed to restart: {}".format(", ".join(nok)), "danger")
        flash("Succesfully restarted {} workers".format(len(response)), "success")

        return redirect(request.referrer)

    @requires_role("admin")
    @route("/restart", methods=["GET"])
    def restart_system(self):
        self.restart_beat(restart_workers=True)
        flash("System restarted", "success")
        return redirect(request.referrer)

    @requires_role("admin")
    @route("/restart/beat")
    def restart_beat(self, restart_workers=False):
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
            if restart_workers:
                ScheduleEntry.unlock_all()
                self.restart_worker()
            p = subprocess.Popen(cmd.split(" "))
            flash("Scheduler restarted successfully (PID: {})".format(p.pid), "success")
        else:
            flash("Error restaring scheduler", "danger")

        return redirect(request.referrer)

    @requires_role("admin")
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
        if results["registered"]:
            for key in results["registered"]:
                registered[key] = {
                    "processes": results["stats"][key]["pool"]["processes"],
                    "active": len(results["active"][key]) > 0,
                }

        active = {}
        if results["active"]:
            for key in results["active"]:
                entries = []
                for item in results["active"][key]:
                    args = item.get("args", [])
                    entries.extend([ScheduleEntry.objects.get(id=id_) for id_ in args])
                active[key] = {"running": entries}

        return render_template(
            "system/system.html",
            registered=registered,
            active=active,
        )
