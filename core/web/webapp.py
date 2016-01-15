import os

from flask import Flask, url_for
from flask.ext.misaka import Misaka

from core.web.json import JSONDecoder
from core.web.api import api
from core.web.frontend import frontend

from core.scheduling import Scheduler
Scheduler()  # load all schedule modules


webapp = Flask(__name__)
webapp.json_decoder = JSONDecoder
Misaka(webapp)

webapp.secret_key = os.urandom(24)
webapp.debug = True

webapp.register_blueprint(api, url_prefix='/api')
webapp.register_blueprint(frontend)


@webapp.route('/list_routes')
def list_routes():
    import urllib
    output = []
    for rule in webapp.url_map.iter_rules():

        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
        output.append(line)

    for line in sorted(output):
        print line

    return "ASD"
