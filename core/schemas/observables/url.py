from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

class Url(Observable):
    value: str
    type: Literal['url'] = ObservableType.url
