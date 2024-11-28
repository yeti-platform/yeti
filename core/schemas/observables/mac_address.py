from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class MacAddress(observable.Observable):
    type: Literal["mac_address"] = "mac_address"

    @classmethod
    def validator(cls, value: str) -> bool:
        return validators.mac_address(value) or False
