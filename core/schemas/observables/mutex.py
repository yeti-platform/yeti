from typing import Literal

from core.schemas import observable


class Mutex(observable.Observable):
    type: Literal[observable.ObservableType.mutex] = observable.ObservableType.mutex


observable.TYPE_MAPPING[observable.ObservableType.mutex] = Mutex
