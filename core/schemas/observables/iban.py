from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class IBAN(observable.Observable):
    type: Literal["iban"] = "iban"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = observable.refang(value)
        if not validators.iban(value):
            raise ValueError("Invalid IBAN")
        return value
