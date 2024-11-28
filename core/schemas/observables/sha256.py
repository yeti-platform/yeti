from typing import Literal

import validators

from core.schemas import observable


class SHA256(observable.Observable):
    type: Literal["sha256"] = "sha256"

    @classmethod
    def validator(cls, value: str) -> bool:
        return validators.sha256(value) or False
