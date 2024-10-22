from typing import Literal

import validators

from core.schemas import observable


class Email(observable.Observable):
    type: Literal[observable.ObservableType.email] = observable.ObservableType.email

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.email(value)
