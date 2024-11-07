from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class SHA1(observable.Observable):
    type: Literal["sha1"] = "sha1"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not validators.sha1(value):
            raise ValueError("Invalid sha1 hash")
        return value
