from typing import Literal

from core.schemas import observable


class Generic(observable.Observable):
    """Use this type of Observable for any type of observable that doesn't fit into any other category."""
    type: observable.ObservableType = observable.ObservableType.generic
