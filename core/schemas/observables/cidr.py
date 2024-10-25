from typing import Literal

from core.schemas import observable


class CIDR(observable.Observable):
    type: Literal["cidr"] = "cidr"
