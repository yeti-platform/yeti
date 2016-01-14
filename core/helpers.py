import re
import collections
from datetime import timedelta
from tldextract import extract

ip_regex = r'([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})'
hostname_regex = r"((([\w\-]+\.)*)([\w\-]+))\.?"
email_regex = r"([\w\-\.\_]+@(([\w\-]+\.)+)([a-zA-Z]{2,6}))\.?"
hash_regex = r"([a-fA-F0-9]{32,64})"
url_regex = r"""
            (
              ((?P<scheme>[\w]{2,9}):\/\/)?
              ([\S]*\:[\S]*\@)?
              (?P<hostname>(
                          ((([\w\-]+\.)+)([a-zA-Z]{2,6}))
                          |([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})
                          |([\w\-]+)
                          )
              )
              (\:[\d]{1,5})?
              (?P<path>(\/[\S]*)?
                (\?[\S]*)?
                (\#[\S]*)?)
            )
        """

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


def is_url(url):
    url = refang(url)
    match = re.match("^" + url_regex + "$", url, re.VERBOSE)
    if match:
        url = match.group(1)
        if url.find('/') != -1:
            return match.group(1)
    else:
        return None


def is_ip(ip):
    if ip:
        match = re.match("^" + ip_regex + "$", ip)
        if match:
            return match.group(1)
    else:
        return False


def is_hostname(hostname):
    hostname = hostname.lower()
    if hostname:
        match = re.match("^" + hostname_regex + "$", hostname)
        if match:
            if hostname.endswith('.'):
                hostname = hostname[:-1]

            parts = extract(hostname)
            if parts.suffix and parts.domain:
                return hostname

    return False


def del_from_set(s, value):
    try:
        s.remove(value)
    except KeyError:
        pass


def iterify(element):
    if element is None:
        return ()
    elif isinstance(element, collections.Iterable) and not isinstance(element, basestring):
        return element
    else:
        return (element,)
