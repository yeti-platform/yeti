from typing import Literal

from core.schemas import observable


class BIC(observable.Observable):
    type: Literal[observable.ObservableType.bic] = observable.ObservableType.bic


observable.TYPE_MAPPING[observable.ObservableType.bic] = BIC
