from inspect import ismethod
from flask_restful import abort


def get_object_or_404(klass, *args, **kwargs):
    try:
        return klass.objects.get(*args, **kwargs)
    except:
        abort(404, message="Could not find matching {}".format(klass.__name__))


def find_method(instance, method_name, argument_name):
    if hasattr(instance, method_name):
        obj = getattr(instance, method_name)
        if ismethod(obj):
            return obj

    abort(404, message="Could not find {} '{}'".format(argument_name, method_name))
