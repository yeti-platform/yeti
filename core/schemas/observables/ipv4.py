from core.schemas.observable import Observable
from core.schemas.observable import ObservableType


class IPv4(Observable):
    value: str
    type: ObservableType = ObservableType.ipv4
