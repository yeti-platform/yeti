from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class IPv6(observable.Observable):
    type: Literal["ipv6"] = "ipv6"

    @classmethod
    def validator(cls, value: str) -> bool:
        return validators.ipv6(value) or False
