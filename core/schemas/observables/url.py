from typing import Literal

import validators
from core.schemas import observable
from pydantic import field_validator


class Url(observable.Observable):
    type: Literal["url"] = "url"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = observable.refang(value)
        if not validators.url(value, strict_query=False):
            raise ValueError("Invalid url")
        return value
