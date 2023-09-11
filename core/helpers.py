import hashlib
import re
from datetime import timedelta

timedelta_regex = re.compile(
    r"(((?P<hours>[0-9]{1,2}):)?((?P<minutes>[0-9]{1,2}):))?(?P<seconds>[0-9]{1,2})$"
)


def string_to_timedelta(string):
    d = {k: int(v) for k, v in timedelta_regex.search(string).groupdict().items() if v}
    return timedelta(**d)


def refang(url):
    def http(match):
        return "http{}".format(match.group("real"))

    substitutes = ("me[o0]w", "h..p")
    schema_re = re.compile("^(?P<fake>{})(?P<real>s?://)".format("|".join(substitutes)))
    domain_re = re.compile(r"(\[\.\]|\[\.|\.\]|,)")
    url = schema_re.sub(http, url)
    url = domain_re.sub(".", url)
    return url

def stream_sha256(stream):
    sha256 = hashlib.sha256()

    while True:
        data = stream.read(4096)
        if data:
            sha256.update(data)
        else:
            stream.seek(0, 0)
            break

    return sha256.hexdigest()
