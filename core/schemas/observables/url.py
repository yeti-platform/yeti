from typing import Literal

import validators

from core.schemas import observable


class Url(observable.Observable):
    type: Literal["url"] = "url"

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.url(value)
