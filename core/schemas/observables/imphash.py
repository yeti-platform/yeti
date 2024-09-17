from typing import Literal

from core.schemas import observable


class Imphash(observable.Observable):
    type: Literal[observable.ObservableType.imphash] = observable.ObservableType.imphash
