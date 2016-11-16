from __future__ import unicode_literals

import re
from inspect import ismethod
from functools import wraps

from core.helpers import iterify

from flask import abort
from flask_login import current_user
from mongoengine import Q

SEARCH_REPLACE = {
    'tags': 'tags__name',
}


def requires_permissions(permissions, object_name=None):
    def wrapper(f):
        @wraps(f)
        def inner(*args, **kwargs):
            oname = object_name
            if not oname:
                oname = getattr(args[0], 'klass', getattr(args[0], 'objectmanager', args[0].__class__)).__name__.lower()
            # a user must have all permissions in order to be granted access
            for p in iterify(permissions):
                if not current_user.has_permission(oname, p):
                    # improve this and make it redirect to login
                    abort(401)
            else:
                return f(*args, **kwargs)
        return inner
    return wrapper


def requires_role(*roles):
    def wrapper(f):
        @wraps(f)
        def inner(*args, **kwargs):
            # a user needs at least one of the roles to be granted access
            for r in iterify(roles[0]):
                if current_user.is_role(r):
                    return f(*args, **kwargs)
            else:
                abort(401)
        return inner
    return wrapper


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


def get_queryset(collection, filters, regex, ignorecase):
    result_filters = dict()

    queryset = collection.objects
    if "order_by" in filters:
        queryset = queryset.order_by(filters.pop("order_by"))

    for key, value in filters.items():
        key = key.replace(".", "__")
        if key in SEARCH_REPLACE:
            key = SEARCH_REPLACE[key]

        if regex and isinstance(value, basestring):
            flags = 0
            if ignorecase:
                flags |= re.I
            value = re.compile(value, flags=flags)

        if isinstance(value, list) and not key.endswith("__in"):
            key += "__all"

        result_filters[key] = value

    q = Q()
    for alias in collection.SEARCH_ALIASES:
        if alias in filters:
            q &= Q(**{collection.SEARCH_ALIASES[alias]: result_filters[alias]}) | Q(**{alias: result_filters[alias]})
            result_filters.pop(alias)

    print "Filter: {}".format(result_filters), q.to_query(collection)

    return queryset.filter(**result_filters).filter(q)
