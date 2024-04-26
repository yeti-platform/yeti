from typing import Literal

from core.schemas import observable


class Jarm(observable.Observable):
    """Represents a JARM fingerprint.

    Value should be in the form JARM:<HASH>.
    """

    type: Literal[observable.ObservableType.jarm] = observable.ObservableType.jarm


observable.TYPE_MAPPING[observable.ObservableType.jarm] = Jarm
