import hashlib
import re
from datetime import timedelta

import validators

import core.schemas.entity as entity
import core.schemas.observable as observable
from core.schemas.observable import Observable

REGEXES = [
    (entity.EntityType.exploit, re.compile(r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)")),
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
    if obs.type in TYPE_VALIDATOR_MAP:
        return TYPE_VALIDATOR_MAP[obs.type](obs.value)
    elif obs.type in dict(REGEXES):
        return dict(REGEXES)[obs.type].match(obs.value)
    else:
        return False


def find_type(value: str) -> observable.ObservableType | None:
    for obs_type in TYPE_VALIDATOR_MAP:
        if TYPE_VALIDATOR_MAP[obs_type](value):
            return obs_type
    for type_obs, regex in TYPE_VALIDATOR_MAP.items():
        if regex.match(value):
            return
    return None


TYPE_VALIDATOR_MAP = {
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
