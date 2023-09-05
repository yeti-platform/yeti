from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class CIDR(Observable):
    value: str
    type: ObservableType = ObservableType.cidr
    