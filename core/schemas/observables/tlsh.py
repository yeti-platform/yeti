from typing import Literal

from core.schemas import observable


class TLSH(observable.Observable):
    type: Literal["tlsh"] = "tlsh"
