from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

class IPv6(Observable):
    value: str
    type: Literal['ip'] = ObservableType.ip
