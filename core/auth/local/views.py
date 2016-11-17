from flask import Blueprint, render_template, request, redirect, flash, abort
from flask_login import login_user, logout_user, current_user
from mongoengine.errors import DoesNotExist
from werkzeug.security import check_password_hash

from core.auth.local.user_management import authenticate, create_user, set_password
from core.user import User


auth = Blueprint('auth', __name__, template_folder='templates')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    else:
        u = authenticate(request.form.get('login'), request.form.get('password'))
        if u:
            login_user(u)
            print "User logged in (web):", u
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


@auth.route('/createuser/<username>/<password>')
def user(username, password):
    create_user(username, password)
    return redirect('/login')


@auth.route("/changepassword", methods=['POST'])
def change_password():
    u = current_user
    if current_user.has_role('admin'):
        if request.form.get('username'):
            try:
                u = User.objects.get(username=request.form.get('username'))
            except DoesNotExist:
                abort(404)

    current = request.form.get("current", "")
    new = request.form.get("new", "")
    bis = request.form.get("bis", "")

    if not check_password_hash(u.password, current):
        flash('Current password is invalid', 'danger')
    elif new != bis:
        flash('Password confirmation differs from new password.', 'danger')
    else:
        u = set_password(u, new)
        u.save()
        login_user(u)
        flash('Password was successfully changed.', 'success')

    return redirect(request.referrer)
