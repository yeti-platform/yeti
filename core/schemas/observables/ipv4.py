from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class IPv4(observable.Observable):
    type: Literal["ipv4"] = "ipv4"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = observable.refang(value)
        if not validators.ipv4(value):
            raise ValueError("Invalid ipv4 address")
        return value
