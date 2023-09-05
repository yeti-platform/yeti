from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class IPv6(Observable):
    value: str
    type: ObservableType = ObservableType.ip