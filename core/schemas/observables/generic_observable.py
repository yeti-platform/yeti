from typing import Literal

from core.schemas import observable


class GenericObservable(observable.Observable):
    """Use this type of Observable for any type of observable that doesn't fit into any other category."""

    type: Literal[observable.ObservableType.generic] = observable.ObservableType.generic


observable.TYPE_MAPPING[observable.ObservableType.generic] = GenericObservable
