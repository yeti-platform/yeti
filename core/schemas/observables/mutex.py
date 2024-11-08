from typing import Literal

from core.schemas import observable


class Mutex(observable.Observable):
    type: Literal["mutex"] = "mutex"
