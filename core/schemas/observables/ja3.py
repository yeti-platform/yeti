from typing import Literal

from core.schemas import observable


class JA3(observable.Observable):
    type: Literal["ja3"] = "ja3"
