from __future__ import unicode_literals

import re
from inspect import ismethod
from functools import wraps
import urlparse
from werkzeug.exceptions import Forbidden
from core.helpers import iterify

from flask import abort, request
from flask_login import current_user
from mongoengine import Q

from core.group import Group

SEARCH_REPLACE = {
    'tags': 'tags__name',
}


def requires_permissions(permissions, object_name=None):

    def wrapper(f):

        @wraps(f)
        def inner(*args, **kwargs):
            oname = object_name
            if not oname:
                oname = getattr(
                    args[0], 'klass',
                    getattr(args[0], 'objectmanager',
                            args[0].__class__)).__name__.lower()
            if not current_user.has_role('admin'):
                # a user must have all permissions in order to be granted access
                for p in iterify(permissions):
                    if not current_user.has_permission(oname, p):
                        # improve this and make it redirect to login
                        abort(401)
            return f(*args, **kwargs)

        return inner

    return wrapper


def requires_role(*roles):

    def wrapper(f):

        @wraps(f)
        def inner(*args, **kwargs):
            # a user needs at least one of the roles to be granted access
            for r in iterify(roles[0]):
                if current_user.has_role(r):
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


def get_queryset(collection, filters, regex, ignorecase, replace=True):
    result_filters = dict()

    queryset = collection.objects
    if "order_by" in filters:
        queryset = queryset.order_by(filters.pop("order_by"))

    for key, value in filters.items():
        key = key.replace(".", "__")
        if replace:
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
            q &= Q(**{
                collection.SEARCH_ALIASES[alias]: result_filters[alias]
            }) | Q(**{
                alias: result_filters[alias]
            })
            result_filters.pop(alias)

    print "Filter: {}".format(result_filters), q.to_query(collection)

    return queryset.filter(**result_filters).filter(q)


def different_origin(referer, target):
    p1, p2 = urlparse.urlparse(referer), urlparse.urlparse(target)
    origin1 = p1.scheme, p1.hostname, p1.port
    origin2 = p2.scheme, p2.hostname, p2.port

    return origin1 != origin2


def csrf_protect():
    if request.method not in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        referer = request.headers.get('Referer')
        print referer

        if referer is None or different_origin(referer, request.url_root):
            raise Forbidden(description="Referer check failed.")


def prevent_csrf(func):

    @wraps(func)
    def inner(*args, **kwargs):
        csrf_protect()
        return func(*args, **kwargs)

    return inner


def get_user_groups():
    if current_user.has_role('admin'):
        groups =  Group.objects()
    else:
        groups = Group.objects(members__in=[current_user.id])

    return groups

def group_user_permission(investigation=False):
    """
        This aux func aimed to simplify check if user is admin or in group with perms
    """
    if current_user.has_role('admin'):
        return True

    elif investigation and hasattr(investigation, "sharing"):
        groups = get_user_groups()
        return any([group.id in investigation.sharing for group in groups]) or current_user.id in investigation.sharing
    else:
        return False
