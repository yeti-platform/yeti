import re
from flask import abort

from inspect import ismethod


SEARCH_ALIASES = {
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

    for alias in SEARCH_ALIASES:
        if alias in filters:
            filters[SEARCH_ALIASES[alias]] = filters.pop(alias)

    for key, value in filters.items():
        key = key.replace(".", "__")
        if key in SEARCH_ALIASES:
            key = SEARCH_ALIASES[key]

        if regex and isinstance(value, basestring):
            flags = 0
            if ignorecase:
                flags |= re.I
            value = re.compile(value, flags=flags)

        if isinstance(value, list):
            key += "__all"

        result_filters[key] = value

    print "Filter: {}".format(result_filters)

    return queryset.filter(**result_filters)
