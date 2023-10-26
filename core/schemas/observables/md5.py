from typing import Literal

from core.schemas import observable


class MD5(observable.Observable):
    type: Literal[observable.ObservableType.md5] = observable.ObservableType.md5


observable.TYPE_MAPPING[observable.ObservableType.md5] = MD5
