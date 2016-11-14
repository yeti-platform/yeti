from flask import Blueprint, render_template, request, redirect, flash
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from core.user import User

auth = Blueprint('auth', __name__, template_folder='templates')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    else:
        u = User.authenticate(request.form.get('login'), request.form.get('password'))
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
