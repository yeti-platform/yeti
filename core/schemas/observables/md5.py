from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class MD5(observable.Observable):
    type: Literal["md5"] = "md5"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not validators.md5(value):
            raise ValueError("Invalid md5 hash")
        return value
