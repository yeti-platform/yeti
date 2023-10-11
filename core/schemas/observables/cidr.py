from typing import Literal

from core.schemas import observable


class CIDR(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.cidr] = observable.ObservableType.cidr


observable.TYPE_MAPPING[observable.ObservableType.cidr] = CIDR
