from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

class SHA1(Observable):
    value: str
    type: Literal['sha1'] = ObservableType.sha1
