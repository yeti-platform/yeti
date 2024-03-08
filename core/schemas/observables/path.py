from datetime import datetime
from typing import Literal

from core.schemas import observable


class Path(observable.Observable):
    type: Literal[observable.ObservableType.path] = observable.ObservableType.path
    creation_time: datetime | None
    modification_time: datetime | None
    access_time: datetime | None
    path_encoding: str | None


observable.TYPE_MAPPING[observable.ObservableType.path] = Path
