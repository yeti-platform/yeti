from flask import Blueprint, request, redirect, flash, abort
from flask_login import current_user, login_user, logout_user

from core.auth.apache.user_management import authenticate
from core.user import User

auth = Blueprint("auth", __name__, template_folder="templates")


@auth.route("/login")
def login():
    if current_user.is_authenticated:
        return redirect("/observable/")
    user = authenticate()
    if user:
        login_user(user)
        print("User logged in (web):".format(user))
        return redirect(request.args.get("next", "/"))
    flash("Invalid credentials", "danger")
    abort(401)


@auth.route("/logout")
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect("/login")
