from typing import Literal

from core.schemas import observable


class TLSH(observable.Observable):
    type: Literal[observable.ObservableType.tlsh] = observable.ObservableType.tlsh
