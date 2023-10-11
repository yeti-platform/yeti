from typing import Literal

from core.schemas import observable


class Path(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.path] = observable.ObservableType.path


observable.TYPE_MAPPING[observable.ObservableType.path] = Path
