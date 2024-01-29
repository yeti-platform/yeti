from typing import Literal

from core.schemas import observable


class MacAddress(observable.Observable):
    type: Literal[
        observable.ObservableType.mac_address
    ] = observable.ObservableType.mac_address


observable.TYPE_MAPPING[observable.ObservableType.mac_address] = MacAddress
