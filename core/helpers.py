import re
import collections
from mongoengine import Document
from datetime import timedelta

timedelta_regex = re.compile(r"(((?P<hours>[0-9]{1,2}):)?((?P<minutes>[0-9]{1,2}):))?(?P<seconds>[0-9]{1,2})$")


def string_to_timedelta(string):
    d = {k: int(v) for k, v in timedelta_regex.search(string).groupdict().items() if v}
    return timedelta(**d)


def refang(url):

    def http(match):
        return "http{}".format(match.group('real'))

    substitutes = ('me[o0]w', 'h..p')
    schema_re = re.compile("^(?P<fake>{})(?P<real>s?://)".format("|".join(substitutes)))
    domain_re = re.compile(r"(\[\.\]|,)")
    url = schema_re.sub(http, url)
    url = domain_re.sub(".", url)
    return url


def del_from_set(s, value):
    try:
        s.remove(value)
    except KeyError:
        pass


def iterify(element):
    if element is None:
        return ()
    elif isinstance(element, collections.Iterable) and not isinstance(element, basestring) and not isinstance(element, Document):
        return element
    else:
        return (element,)


def get_value_at(data, path):
    path = path.split('.')

    for path_elt in path:
        if data is None or path_elt not in data:
            return None
        else:
            data = data[path_elt]

    return data
