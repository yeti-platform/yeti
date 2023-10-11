from typing import Literal

from core.schemas import observable


class Email(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.email] = observable.ObservableType.email


observable.TYPE_MAPPING[observable.ObservableType.email] = Email
