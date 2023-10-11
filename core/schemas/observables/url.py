from typing import Literal

from core.schemas import observable


class Url(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.url] = observable.ObservableType.url


observable.TYPE_MAPPING[observable.ObservableType.url] = Url
