import os

from flask import Flask, url_for, request
from flask.ext.login import LoginManager, login_required, current_user
from flask.ext.misaka import Misaka

from core.user import User
from core.web.json import JSONDecoder
from core.web.api import api
from core.web.frontend import frontend

from core.scheduling import Scheduler
Scheduler()  # load all schedule modules

webapp = Flask(__name__)
webapp.secret_key = os.urandom(24)
webapp.json_decoder = JSONDecoder
webapp.debug = True

Misaka(webapp)

login_manager = LoginManager()
login_manager.init_app(webapp)


# Handle authentication
@login_manager.user_loader
def load_user(user_id):
    print "user:", user_id
    try:
        return User.get(user_id)
    except:
        return None

login_manager.anonymous_user = User.get_default_user


@api.before_request
@login_required
def api_login_required():
    pass


@frontend.before_request
def frontend_login_required():
    if not current_user.is_authenticated():
        if (request.endpoint and request.endpoint != 'frontend.static'):
            return login_manager.unauthorized()


webapp.register_blueprint(frontend)
webapp.register_blueprint(api, url_prefix='/api')


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

    return "<br>".join(output)

@webapp.template_test()
def startswith(string, pattern):
    return string.startswith(pattern)
