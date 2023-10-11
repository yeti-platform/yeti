from typing import Literal

from core.schemas import observable


class SHA256(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.sha256] = observable.ObservableType.sha256


observable.TYPE_MAPPING[observable.ObservableType.sha256] = SHA256
