from typing import Literal

import validators

from core.schemas import observable


class IBAN(observable.Observable):
    type: Literal[observable.ObservableType.iban] = observable.ObservableType.iban

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.iban(value)
