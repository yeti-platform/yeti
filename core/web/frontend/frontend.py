from flask import Blueprint, request, render_template

frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")


@frontend.route('/')
def index():
    return render_template('index.html')
    return "It works!"
