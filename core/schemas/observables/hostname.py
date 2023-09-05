from core.schemas.observable import Observable
from core.schemas.observable import ObservableType


class Hostname(Observable):
    value: str
    type: ObservableType = ObservableType.hostname
