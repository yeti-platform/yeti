from typing import Literal

from core.schemas import observable


class JA3(observable.Observable):
    type: Literal[observable.ObservableType.ja3] = observable.ObservableType.ja3
