from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class IBAN(observable.Observable):
    type: Literal["iban"] = "iban"

    @classmethod
    def validator(cls, value: str) -> bool:
        return validators.iban(value) or False
