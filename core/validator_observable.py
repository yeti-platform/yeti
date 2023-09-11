
import validators
from core.schemas import observable
from core.schemas import entity
import re

REGEXES = [
    (entity.EntityType.exploit, re.compile(r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)")),
]

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

def validate_observable(obs: observable.Observable) -> bool:
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
    for type_obs, regex in REGEXES:
        if regex.match(value):
            return
    return None