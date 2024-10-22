from typing import Literal

from core.schemas import observable


class Ssdeep(observable.Observable):
    type: Literal[observable.ObservableType.ssdeep] = observable.ObservableType.ssdeep
