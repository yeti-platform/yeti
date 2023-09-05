import hashlib
import re
from datetime import timedelta

from core.schemas.observable import Observable
import validators
import core.schemas.observable as observable

REGEXES = [
    ("ip", re.compile(r"(?P<pre>\W?)(?P<search>(?:\d{1,3}\.){3}\d{1,3})(?P<post>\W?)")),
    (
        "hostname",
        re.compile(r"(?P<pre>\W?)(?P<search>[-.\w[\]]+\[?\.\]?[\w-]+)(?P<post>\W?)"),
    ),
    (
        "url",
        re.compile(
            r"(?P<search>((?P<scheme>[\w]{2,9}):\/\/)?([\S]*\:[\S]*\@)?(?P<hostname>"
            + r"[-.\w[\]]+\[?\.\]?[\w-]+"
            + r")(\:[\d]{1,5})?(?P<path>((\/[^\?]*?)?(\?[^#]*?)?(\#.*?)?)[\w/])?)"
        ),
    ),
    (
        "email",
        re.compile(
            r"(?P<pre>\W?)(?P<search>[\w-]+(?:\.[\w-]+)*@(?:[\w-]+\.)+[\w-]+)(?P<post>\W?)"
        ),
    ),
    ("md5", re.compile(r"(?P<pre>\W?)(?P<search>[a-fA-F\d]{32})(?P<post>\W?)")),
    ("sha1", re.compile(r"(?P<pre>\W?)(?P<search>[a-fA-F\d]{40})(?P<post>\W?)")),
    ("sha256", re.compile(r"(?P<pre>\W?)(?P<search>[a-fA-F\d]{64})(?P<post>\W?)")),
    ("sha512", re.compile(r"(?P<pre>\W?)(?P<search>[a-fA-F\d]{128})(?P<post>\W?)")),
    ("cve", re.compile(r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)")),
]

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


def validate_observable(obs: Observable) -> bool:
    if obs.type in _MAPPING_VALIDATORS:
        return _MAPPING_VALIDATORS[obs.type](obs.value)
    else:
        if obs.type in dict(REGEXES):
            return dict(REGEXES)[obs.type].match(obs.value)



_MAPPING_VALIDATORS = {
    observable.ObservableType.ip: validators.ipv4,
    observable.ObservableType.bitcoin_wallet: validators.btc_address,
    observable.ObservableType.sha256: validators.sha256,
    observable.ObservableType.sha1: validators.sha1,
    observable.ObservableType.md5: validators.md5,
    observable.ObservableType.hostname: validators.domain,
    observable.ObservableType.url: validators.url,
    observable.ObservableType.email: validators.email,
}


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
