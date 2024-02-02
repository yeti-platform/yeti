import datetime
import hashlib
import re


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


def now():
    return datetime.datetime.now(datetime.timezone.utc)
    