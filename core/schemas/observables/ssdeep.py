from typing import Literal

from core.schemas import observable


class Ssdeep(observable.Observable):
    type: Literal["ssdeep"] = "ssdeep"
