from typing import Literal

from core.schemas import observable


class SHA1(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.sha1] = observable.ObservableType.sha1


observable.TYPE_MAPPING[observable.ObservableType.sha1] = SHA1
