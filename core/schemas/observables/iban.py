from typing import Literal

from core.schemas import observable


class IBAN(observable.Observable):
    type: Literal[observable.ObservableType.iban] = observable.ObservableType.iban


observable.TYPE_MAPPING[observable.ObservableType.iban] = IBAN
