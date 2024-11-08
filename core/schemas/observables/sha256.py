from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class SHA256(observable.Observable):
    type: Literal["sha256"] = "sha256"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not validators.sha256(value):
            raise ValueError("Invalid sha256 hash")
        return value
