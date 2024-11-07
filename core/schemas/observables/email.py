from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class Email(observable.Observable):
    type: Literal["email"] = "email"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = observable.refang(value)
        if not validators.email(value):
            raise ValueError("Invalid email address")
        return value
