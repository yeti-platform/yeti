from __future__ import unicode_literals

import re
from inspect import ismethod

from flask import abort
from mongoengine import *


SEARCH_ALIASES = {
    'name': 'aliases',
}

SEARCH_REPLACE = {
    'tags': 'tags__name',
}


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
    for alias in SEARCH_ALIASES:
        if alias in filters:
            q &= Q(**{SEARCH_ALIASES[alias]: result_filters[alias]}) | Q(**{alias: result_filters[alias]})
            result_filters.pop(alias)

    print "Filter: {}".format(result_filters), q.to_query(collection)

    return queryset.filter(**result_filters).filter(q)
