from datetime import datetime
from typing import Literal

from core.schemas import observable


class Path(observable.Observable):
    type: Literal[observable.ObservableType.path] = observable.ObservableType.path
    creation_time: datetime | None = None
    modification_time: datetime | None = None
    access_time: datetime | None = None
    path_encoding: str | None = None


observable.TYPE_MAPPING[observable.ObservableType.path] = Path
