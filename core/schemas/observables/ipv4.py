from typing import Literal

import validators

from core.schemas import observable


class IPv4(observable.Observable):
    type: Literal["ipv4"] = "ipv4"

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.ipv4(value)
