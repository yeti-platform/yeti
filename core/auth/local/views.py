from flask import Blueprint, render_template, request, redirect, flash, abort
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash

from core.auth.local.user_management import authenticate, create_user, set_password
from core.user import User
from core.web.helpers import get_object_or_404

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


@auth.route('/createuser', methods=["POST"])
def new_user():
    username = request.form.get("username")
    password = request.form.get("password")
    if type(current_user) != AnonymousUserMixin and current_user.has_role('admin') and current_user.is_active:
        create_user(username, password)
    return redirect(request.referrer)


@auth.route("/change-password", methods=['POST'])
def change_password():
    if current_user.has_role('admin') and request.args.get('id'):
        u = get_object_or_404(User, id=request.args.get('id'))
    else:
        u = current_user

    current = request.form.get("current", "")
    new = request.form.get("new", "")
    bis = request.form.get("bis", "")

    if not current_user.has_role('admin'):
        if not check_password_hash(u.password, current):
            flash('Current password is invalid', 'danger')
            return redirect(request.referrer)

    if new != bis:
        flash('Password confirmation differs from new password.', 'danger')
    else:
        u = set_password(u, new)
        u.save()
        # re-execute the login if the changes were made on current_user
        if u.id == current_user.id:
            login_user(u)
        flash('Password was successfully changed.', 'success')

    return redirect(request.referrer)
