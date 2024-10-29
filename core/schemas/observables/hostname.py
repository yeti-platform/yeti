from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class Hostname(observable.Observable):
    type: Literal["hostname"] = "hostname"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = observable.refang(value)
        if not validators.domain(value):
            raise ValueError("Invalid hostname")
        return value
