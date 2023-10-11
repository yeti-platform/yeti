from typing import Literal

from core.schemas import observable


class SsdeepHash(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.ssdeep] = observable.ObservableType.ssdeep


observable.TYPE_MAPPING[observable.ObservableType.ssdeep] = SsdeepHash
