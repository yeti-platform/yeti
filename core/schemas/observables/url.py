from core.schemas.observable import Observable
from core.schemas.observable import ObservableType


class Url(Observable):
    value: str
    type: ObservableType = ObservableType.url
