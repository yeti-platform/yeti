from flask import Blueprint, request, render_template

from core.observables import Observable

frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")


@frontend.route('/')
def browse():
    return render_template('browse.html')


@frontend.route('/observables/<id>')
def observable(id):
    o = Observable.objects.get(id=id)
    return render_template('observable.html', observable=o)
