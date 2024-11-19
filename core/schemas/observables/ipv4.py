from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class IPv4(observable.Observable):
    type: Literal["ipv4"] = "ipv4"

    @field_validator("value", mode="before")
    def refang(cls, v) -> str:
        return observable.refang(v)

    @classmethod
    def validator(cls, value: str) -> bool:
        return validators.ipv4(value) or False
