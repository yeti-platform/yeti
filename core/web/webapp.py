import os

from flask import Flask
from flask.ext.misaka import Misaka

from core.web.api import api
from core.web.frontend import frontend


webapp = Flask(__name__)
Misaka(webapp)

webapp.secret_key = os.urandom(24)
webapp.debug = True

webapp.register_blueprint(api, url_prefix='/api')
webapp.register_blueprint(frontend)
