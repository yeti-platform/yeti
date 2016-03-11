from flask import abort

from inspect import ismethod


def get_object_or_404(klass, *args, **kwargs):
    try:
        return klass.objects.get(*args, **kwargs)
    except:
        abort(404)


def find_method(instance, method_name, argument_name):
    if method_name and hasattr(instance, method_name):
        obj = getattr(instance, method_name)
        if ismethod(obj):
            return obj
    abort(404)
