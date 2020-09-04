from flask import Blueprint, abort, redirect, request, session
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash

from core.auth import common
from core.auth.local.group_management import create_group
from core.auth.local.user_management import (authenticate, create_user,
                                             set_password)
from core.user import User
from core.web.api.api import render
from core.web.helpers import get_object_or_404

auth = Blueprint('auth', __name__)


@auth.route('/auth/login', methods=['GET', 'POST'])
def login_redirect():
    # The browser will request /auth/login, redirect to the VueJS login page.
    return redirect('/login')


@auth.route('/api/auth/login', methods=['GET', 'POST'])
def login():
    params = request.get_json()
    user = authenticate(params['user'], params['password'])
    if not user:
        return {'error': f'Invalid credentials for {params["user"]}.'}, 401

    common.generate_session_token(user)
    login_user(user)

    return {'authenticated': True, 'user': user.username}

@auth.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    """Logout user."""
    logout_user()
    session.clear()
    return {'authenticated': False}

@auth.route('/api/createuser', methods=["POST"])
@login_required
def api_new_user():
    params = request.get_json()
    username = params['username'].encode()
    password = params['password'].encode()
    admin = params['admin']
    if current_user.has_role('admin') and current_user.is_active:
        try:
            user = create_user(username, password, admin=admin)
        except RuntimeError as error:
            return render({'error': str(error)}), 400
        return render(user)
    abort(401)

@auth.route('/api/creategroup', methods=["POST"])
@login_required
def api_new_group():
    params = request.get_json()
    groupname = params.get("groupname")
    if not current_user.has_role('admin') and current_user.is_active:
        abort(401)
    group = create_group(groupname)
    if not group:
        return render({'error': f'Group {groupname} already exists.'}), 400
    return render(group)

@auth.route("/api/users/change-password", methods=['POST'])
def change_password():
    params = request.get_json()
    if current_user.has_role('admin') and params.get('id'):
        u = get_object_or_404(User, id=params.get('id'))
    else:
        u = current_user

    current = params.get("current")
    new = params.get("new")

    if not (current and new):
        return render({
            'error': 'You must specify both current and new password'
            }), 400

    if not current_user.has_role('admin'):
        if not check_password_hash(u.password, current):
            return render({'error': 'Invalid password'}), 400
    else:
        u = set_password(u, new)
        u.save()
        # re-execute the login if the changes were made on current_user
        if u.id == current_user.id:
            login_user(u)
        return {}
