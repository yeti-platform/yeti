from core.schemas import observable
from typing import Literal


class TLSH(observable.Observable):
    type: Literal[observable.ObservableType.tlsh] = observable.ObservableType.tlsh


observable.TYPE_MAPPING[observable.ObservableType.tlsh] = TLSH
