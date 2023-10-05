from core.schemas.observable import Observable, ObservableType
from typing import Literal


class TLSH(Observable):
    value: str
    type: Literal["tlsh"] = ObservableType.tlsh
