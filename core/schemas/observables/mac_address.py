from typing import Literal

from core.schemas import observable


class MacAddress(observable.Observable):
    type: Literal["mac_address"] = "mac_address"
