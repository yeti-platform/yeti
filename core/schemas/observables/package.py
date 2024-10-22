from typing import Literal

from core.schemas import observable


class Package(observable.Observable):
    type: Literal[observable.ObservableType.package] = observable.ObservableType.package
    version: str = None
    regitry_type: str = None
