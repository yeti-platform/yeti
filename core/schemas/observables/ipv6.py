from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class IPv6(observable.Observable):
    type: Literal["ipv6"] = "ipv6"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = observable.refang(value)
        if not validators.ipv6(value):
            raise ValueError("Invalid ipv6 address")
        return value
