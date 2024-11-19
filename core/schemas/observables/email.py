from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class Email(observable.Observable):
    type: Literal["email"] = "email"

    @field_validator("value", mode="before")
    def refang(cls, v) -> str:
        return observable.refang(v)

    @classmethod
    def validator(cls, value: str) -> bool:
        return validators.email(value) or False
