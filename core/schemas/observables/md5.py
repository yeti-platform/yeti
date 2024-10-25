from typing import Literal

import validators

from core.schemas import observable


class MD5(observable.Observable):
    type: Literal["md5"] = "md5"

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.md5(value)
