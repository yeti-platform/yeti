from typing import Literal

import validators

from core.schemas import observable


class Hostname(observable.Observable):
    type: Literal["hostname"] = "hostname"

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.domain(value)
