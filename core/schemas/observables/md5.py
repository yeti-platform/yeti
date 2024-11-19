from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class MD5(observable.Observable):
    type: Literal["md5"] = "md5"

    @classmethod
    def validator(cls, value: str) -> bool:
        return validators.md5(value) or False
