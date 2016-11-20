# from flask import request, abort, make_response, send_file, url_for
from core.web.api.crud import CrudSearchApi, CrudApi

from core.user import User
# from core.web.api.api import render


class UserAdminSearch(CrudSearchApi):
    template = 'user_api.html'
    objectmanager = User
