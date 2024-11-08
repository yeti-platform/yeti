from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class MacAddress(observable.Observable):
    type: Literal["mac_address"] = "mac_address"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not validators.mac_address(value):
            raise ValueError("Invalid mac address")
        return value
