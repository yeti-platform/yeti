from typing import Literal

from core.schemas import observable


class JARM(observable.Observable):
    type: Literal["jarm"] = "jarm"
