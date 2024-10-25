from typing import Literal

import validators

from core.schemas import observable


class SHA1(observable.Observable):
    type: Literal["sha1"] = "sha1"

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.sha1(value)
