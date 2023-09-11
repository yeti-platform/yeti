
import validators
from core.schemas.observable import ObservableType
from core.schemas.observable import Observable
from core.schemas import entity
import re

REGEXES = [
    (entity.EntityType.exploit, re.compile(r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)")),
]

TYPE_VALIDATOR_MAP = {
    ObservableType.ip: validators.ipv4,
    ObservableType.bitcoin_wallet: validators.btc_address,
    ObservableType.sha256: validators.sha256,
    ObservableType.sha1: validators.sha1,
    ObservableType.md5: validators.md5,
    ObservableType.hostname: validators.domain,
    ObservableType.url: validators.url,
    ObservableType.email: validators.email,
}

def validate_observable(obs: Observable) -> bool:
    if obs.type in TYPE_VALIDATOR_MAP:
        return TYPE_VALIDATOR_MAP[obs.type](obs.value)
    elif obs.type in dict(REGEXES):
        return dict(REGEXES)[obs.type].match(obs.value)
    else:
        return False


def find_type(value: str) -> ObservableType | None:
    for obs_type in TYPE_VALIDATOR_MAP:
        if TYPE_VALIDATOR_MAP[obs_type](value):
            return obs_type
    for type_obs, regex in REGEXES:
        if regex.match(value):
            return
    return None