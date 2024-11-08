import re
from typing import Literal

from pydantic import field_validator

from core.schemas import observable

BIC_MATCHER_REGEX = re.compile("^[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{3}?")


class BIC(observable.Observable):
    type: Literal["bic"] = "bic"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not BIC_MATCHER_REGEX.match(value):
            raise ValueError("Invalid BIC")
        return value
