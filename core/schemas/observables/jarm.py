from typing import Literal

from core.schemas import observable


class JARM(observable.Observable):
    type: Literal[observable.ObservableType.jarm] = observable.ObservableType.jarm


observable.TYPE_MAPPING[observable.ObservableType.ja3] = JARM
