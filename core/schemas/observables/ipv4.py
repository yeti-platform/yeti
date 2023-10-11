from typing import Literal

from core.schemas import observable


class IPv4(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.ipv4] = observable.ObservableType.ipv4


observable.TYPE_MAPPING[observable.ObservableType.ipv4] = IPv4
