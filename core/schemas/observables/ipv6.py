from typing import Literal

from core.schemas import observable


class IPv6(observable.Observable):
    type: Literal[observable.ObservableType.ipv6] = observable.ObservableType.ipv6


observable.TYPE_MAPPING[observable.ObservableType.ipv6] = IPv6
