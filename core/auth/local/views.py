from flask import Blueprint, render_template, request, redirect, flash, abort
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash

from core.auth.local.group_management import create_group
from core.auth.local.user_management import authenticate, create_user, \
    set_password
from core.user import User
from core.web.helpers import get_object_or_404
from core.web.api.api import render

auth = Blueprint('auth', __name__, template_folder='templates')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect("/observable/")
    if request.method == 'GET':
        return render_template('login.html')

    else:
        u = authenticate(
            request.form.get('login'), request.form.get('password'))
        if u:
            login_user(u)
            print("User logged in (web):")
            redir = request.args.get('next', '/')
            return redirect(redir)
        else:
            flash("Invalid credentials", "danger")
            return render_template('login.html')


@auth.route('/logout')
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect('/login')

# TODO: newfrontend-deprecation
# Remove this function when the new frontend is the default
@auth.route('/createuser', methods=["POST"])
@login_required
def new_user():
    username = request.form.get("username")
    password = request.form.get("password")
    admin = request.form.get("admin") is not None
    if current_user.has_role('admin') and current_user.is_active:
        create_user(username, password, admin=admin)
    return redirect(request.referrer)

    logout_user()


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

@auth.route('/creategroup', methods=["POST"])
@login_required
def new_group():
    groupname = request.form.get("groupname")
    if current_user.has_role('admin') and current_user.is_active:
        create_group(groupname)
    return redirect(request.referrer)

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

@auth.route("/api/change-password", methods=['POST'])
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
