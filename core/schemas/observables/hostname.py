from typing import Literal

from core.schemas import observable


class Hostname(observable.Observable):
    type: Literal[observable.ObservableType.hostname] = observable.ObservableType.hostname


observable.TYPE_MAPPING[observable.ObservableType.hostname] = Hostname
